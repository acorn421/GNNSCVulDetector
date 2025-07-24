/*
 * ===== SmartInject Injection Details =====
 * Function      : transferOwnership
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 1 findings
 * Total Found   : 2 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the newOwner address before updating the owner state. This creates a critical window where:
 * 
 * 1. **State Inconsistency**: The OwnershipTransferred event is emitted but the owner hasn't been updated yet
 * 2. **External Call Window**: The newOwner can execute arbitrary code while the old owner is still in control
 * 3. **Multi-Transaction Exploitation**: 
 *    - Transaction 1: Owner calls transferOwnership(maliciousContract)
 *    - During the external call, maliciousContract can call back into the contract while old owner state persists
 *    - Transaction 2+: The malicious contract can exploit the inconsistent state in subsequent transactions
 *    - The vulnerability requires multiple function calls across transactions to fully exploit
 * 
 * The vulnerability violates the Checks-Effects-Interactions pattern by performing external interaction before the critical state update. This is realistic as developers often add notification mechanisms without considering reentrancy implications. The exploit requires state accumulation across multiple transactions - the initial call creates the vulnerable state, and subsequent transactions can exploit it.
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
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // VULNERABILITY: External call before state update creates reentrancy window
        // Notify new owner about ownership transfer
        if (newOwner.call(bytes4(keccak256("onOwnershipReceived(address)")), owner)) {
            // Call succeeded, continue with transfer
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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

contract NHICoin is Ownable, ERC20Token {
    event Burn(address indexed from, uint256 value);

    function NHICoin (
        string name, 
        string symbol, 
        uint256 decimals, 
        uint256 totalSupply
    ) ERC20Token (name, symbol, decimals, totalSupply) public {}

    function() payable public {
        revert();
    }

    function burn(uint256 _value) onlyOwner public returns (bool success) {
        require(balanceOf[msg.sender] >= _value);
        balanceOf[msg.sender] = balanceOf[msg.sender].sub(_value);
        totalSupply = totalSupply.sub(_value);
        Burn(msg.sender, _value);
        return true;
    }
}