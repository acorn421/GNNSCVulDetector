/*
 * ===== SmartInject Injection Details =====
 * Function      : burn
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 3 findings
 * Total Found   : 4 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-benign (SWC-107)
 * 3. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by implementing a two-phase burn process with external registry callbacks. The vulnerability requires multiple transactions to exploit:
 * 
 * **Specific Changes Made:**
 * 1. Added `burnPending` mapping to track pending burn amounts per user
 * 2. Split burn operation into two phases: initiation and execution
 * 3. Added external calls to `IBurnRegistry` before state updates in both phases
 * 4. Violated CEI pattern by calling external contracts before updating critical state
 * 
 * **Multi-Transaction Exploitation:**
 * 1. **Transaction 1**: Owner calls `burn(amount)` → Sets `burnPending[owner] = amount` → External call to `onBurnInitiated()`
 * 2. **During external call**: Registry contract can reenter and call `burn(amount)` again
 * 3. **Transaction 2**: Owner calls `burn(amount)` again → Checks `burnPending[owner] == amount` → External call to `onBurnExecuted()` before clearing pending state
 * 4. **During second external call**: Registry can reenter and exploit the fact that `burnPending` is still set but balance/totalSupply haven't been updated yet
 * 
 * **Why Multiple Transactions Are Required:**
 * - The vulnerability relies on the persistent `burnPending` state between transactions
 * - First transaction sets up the vulnerable state, second transaction exploits it
 * - Single transaction exploitation is prevented by the two-phase validation logic
 * - The registry contract needs to accumulate state across multiple burn initiations to maximize exploitation
 * - Attack requires coordinated sequence: setup → accumulate → exploit across multiple calls
 * 
 * **Realistic Attack Scenario:**
 * A malicious registry contract could:
 * 1. Track multiple burn initiations across different transactions
 * 2. During `onBurnExecuted()` callback, reenter to initiate new burns
 * 3. Exploit the window where `burnPending` is set but tokens aren't actually burned yet
 * 4. Accumulate pending burns beyond owner's actual balance through reentrancy chains
 */
pragma solidity ^0.4.18;

contract Ownable {
    address public owner;
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    function Ownable() public {
        owner = msg.sender;
    }

    modifier onlyOwner() {
        require(msg.sender == owner);
        _;
    }

    function transferOwnership(address newOwner) public onlyOwner {
        require(newOwner != address(0));
        OwnershipTransferred(owner, newOwner);
        owner = newOwner;
    }
}

library SafeMath {
    function mul(uint256 a, uint256 b) internal pure returns (uint256) {
        if (a == 0) {
            return 0;
        }
        uint256 c = a * b;
        assert(c / a == b);
        return c;
    }

    function div(uint256 a, uint256 b) internal pure returns (uint256) {
        uint256 c = a / b;
        return c;
    }

    function sub(uint256 a, uint256 b) internal pure returns (uint256) {
        assert(b <= a);
        return a - b;
    }

    function add(uint256 a, uint256 b) internal pure returns (uint256) {
        uint256 c = a + b;
        assert(c >= a);
        return c;
    }
}

contract ERC20Token {
    using SafeMath for uint256;

    string public name;
    string public symbol;
    uint256 public decimals;
    uint256 public totalSupply;

    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);

    function ERC20Token (
        string _name, 
        string _symbol, 
        uint256 _decimals, 
        uint256 _totalSupply) public 
    {
        name = _name;
        symbol = _symbol;
        decimals = _decimals;
        totalSupply = _totalSupply * 10 ** decimals;
        balanceOf[msg.sender] = totalSupply;
    }

    function _transfer(address _from, address _to, uint256 _value) internal {
        require(_to != 0x0);
        require(balanceOf[_from] >= _value);
        require(balanceOf[_to].add(_value) > balanceOf[_to]);
        uint256 previousBalances = balanceOf[_from].add(balanceOf[_to]);
        balanceOf[_from] = balanceOf[_from].sub(_value);
        balanceOf[_to] = balanceOf[_to].add(_value);

        Transfer(_from, _to, _value);
        assert(balanceOf[_from].add(balanceOf[_to]) == previousBalances);
    }

    function transfer(address _to, uint256 _value) public returns (bool success) {
        _transfer(msg.sender, _to, _value);
        return true;
    }

    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success) {
        require(_value <= allowance[_from][msg.sender]);
        allowance[_from][msg.sender] = allowance[_from][msg.sender].sub(_value);
        _transfer(_from, _to, _value);
        return true;
    }

    function approve(address _spender, uint256 _value) public returns (bool success) {
        allowance[msg.sender][_spender] = _value;
        Approval(msg.sender, _spender, _value);
        return true;
    }
}

// Interface for burn registry
// type IBurnRegistry is not supported in 0.4.18, so declare as contract.
contract IBurnRegistry {
    function onBurnInitiated(address from, uint256 value) public;
    function onBurnExecuted(address from, uint256 value) public;
}

contract Omnic is Ownable, ERC20Token {
    event Burn(address indexed from, uint256 value);

    // Declare mappings and variables used in burn
    mapping(address => uint256) public burnPending;
    address public burnRegistry;

    function Omnic (
        string name, 
        string symbol, 
        uint256 decimals, 
        uint256 totalSupply
    ) ERC20Token (name, symbol, decimals, totalSupply) public {}

    function() payable public {
        revert();
    }

    function setBurnRegistry(address _registry) public onlyOwner {
        burnRegistry = _registry;
    }

    function burn(uint256 _value) onlyOwner public returns (bool success) {
        require(balanceOf[msg.sender] >= _value);
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Multi-phase burn: initiate burn process first
        if (burnPending[msg.sender] == 0) {
            burnPending[msg.sender] = _value;
            
            // Notify external burn registry before state changes
            if (burnRegistry != address(0)) {
                IBurnRegistry(burnRegistry).onBurnInitiated(msg.sender, _value);
            }
            return true;
        }
        
        // Second phase: complete the burn if pending matches requested
        require(burnPending[msg.sender] == _value);
        uint256 pendingBurn = burnPending[msg.sender];
        
        // External callback before clearing pending state
        if (burnRegistry != address(0)) {
            IBurnRegistry(burnRegistry).onBurnExecuted(msg.sender, pendingBurn);
        }
        
        // Clear pending state and execute burn
        burnPending[msg.sender] = 0;
        balanceOf[msg.sender] = balanceOf[msg.sender].sub(pendingBurn);
        totalSupply = totalSupply.sub(pendingBurn);
        Burn(msg.sender, pendingBurn);
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        return true;
    }
}
