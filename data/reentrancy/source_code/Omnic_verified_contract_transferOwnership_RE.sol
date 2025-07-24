/*
 * ===== SmartInject Injection Details =====
 * Function      : transferOwnership
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 3 findings
 * Total Found   : 6 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-benign (SWC-107)
 * 3. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by implementing a two-step ownership transfer process. The vulnerability requires multiple transactions to exploit:
 * 
 * **Changes Made:**
 * 1. **Added State Variables**: Added `pendingOwnershipTransfer` mapping to track pending transfers and `nominatedOwner` mapping to store nominations
 * 2. **Two-Step Process**: Modified function to require two separate calls - first to nominate, second to confirm
 * 3. **External Calls**: Added external calls to notify the new owner contract during both nomination and confirmation phases
 * 4. **State Manipulation Window**: Created a window where the contract state indicates pending transfer but ownership hasn't changed yet
 * 
 * **Multi-Transaction Exploitation:**
 * 1. **Transaction 1**: Attacker calls `transferOwnership(maliciousContract)` - this sets `pendingOwnershipTransfer[maliciousContract] = true` and makes external call to `onOwnershipNominated()`
 * 2. **In the callback**: Malicious contract can observe that `pendingOwnershipTransfer[maliciousContract] == true` but `owner` is still the original owner
 * 3. **Transaction 2**: Attacker calls `transferOwnership(maliciousContract)` again - this triggers the completion path with another external call to `onOwnershipTransferred()`
 * 4. **In the second callback**: Malicious contract can exploit the intermediate state where the external call happens before the ownership is actually transferred
 * 
 * **Why Multi-Transaction Required:**
 * - The vulnerability exploits the persistent state between transactions where `pendingOwnershipTransfer` is set but ownership hasn't transferred
 * - An attacker can use the first transaction to set up the state, then use the second transaction to exploit the race condition
 * - The external calls provide reentrancy opportunities during both the nomination and confirmation phases
 * - The intermediate state allows the malicious contract to know when ownership transfer is imminent and plan accordingly
 * 
 * This creates a realistic scenario where a malicious contract can exploit the time window between nomination and confirmation to manipulate other contract state or coordinate attacks.
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

    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
    mapping(address => bool) public pendingOwnershipTransfer;
    mapping(address => address) public nominatedOwner;
    
    function transferOwnership(address newOwner) public onlyOwner {
        require(newOwner != address(0));
        
        // If this is a pending transfer, complete it
        if (pendingOwnershipTransfer[newOwner]) {
            // External call to notify the new owner before finalizing
            if (extcodesize(newOwner) > 0) {
                newOwner.call(
                    abi.encodeWithSignature("onOwnershipTransferred(address)", owner)
                );
                // Continue even if call fails
            }
            
            // Clear pending state and finalize transfer
            pendingOwnershipTransfer[newOwner] = false;
            delete nominatedOwner[newOwner];
            OwnershipTransferred(owner, newOwner);
            owner = newOwner;
        } else {
            // First call - set up pending transfer
            pendingOwnershipTransfer[newOwner] = true;
            nominatedOwner[newOwner] = newOwner;
            
            // External call to notify nominated owner
            if (extcodesize(newOwner) > 0) {
                newOwner.call(
                    abi.encodeWithSignature("onOwnershipNominated(address)", owner)
                );
                // Continue even if call fails
            }
        }
// ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
    }
    
    function extcodesize(address _addr) internal view returns (uint256 size) {
        assembly { size := extcodesize(_addr) }
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

contract Omnic is Ownable, ERC20Token {
    event Burn(address indexed from, uint256 value);

    function Omnic (
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