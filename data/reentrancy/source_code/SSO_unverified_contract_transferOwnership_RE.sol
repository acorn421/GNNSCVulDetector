/*
 * ===== SmartInject Injection Details =====
 * Function      : transferOwnership
 * Vulnerability : Reentrancy
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 0 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability in the transferOwnership function. The vulnerability requires multiple transactions to exploit:
 * 
 * **Specific Changes Made:**
 * 1. **Added state variables**: `pendingOwner` to track pending ownership transfer and `ownershipTransferInProgress` mapping to track transfer status
 * 2. **Two-phase ownership transfer**: The function now has two logical phases - initiation and completion
 * 3. **External call before state finalization**: Added a call to `onOwnershipTransferStarted()` on the current owner before completing the ownership transfer
 * 4. **State persistence between phases**: The `ownershipTransferInProgress` flag and `pendingOwner` persist between transactions
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 1. **Transaction 1**: Legitimate owner calls `transferOwnership(newOwner)` 
 *    - `ownershipTransferInProgress[currentOwner] = true`
 *    - `pendingOwner = newOwner`
 *    - External call to `currentOwner.onOwnershipTransferStarted(newOwner)`
 *    - During this external call, if currentOwner is a malicious contract, it can:
 *      - Call `transferOwnership(maliciousOwner)` again (reentrancy)
 *      - The reentrant call will see `ownershipTransferInProgress[currentOwner] = true`
 *      - Set `pendingOwner = maliciousOwner`
 *      - Complete the transfer to `maliciousOwner`
 * 
 * 2. **Transaction 2**: When the original call resumes:
 *    - It checks `ownershipTransferInProgress[msg.sender]` (still true from the reentrant call)
 *    - But `pendingOwner != newOwner` (it was changed to maliciousOwner)
 *    - The condition fails, so ownership doesn't transfer to the intended newOwner
 *    - The malicious owner retains control
 * 
 * **Why Multi-Transaction Dependency is Required:**
 * - The vulnerability requires the state set in the first transaction (`ownershipTransferInProgress`, `pendingOwner`) to persist and be manipulated during the reentrancy
 * - A single transaction attack wouldn't work because the state changes need to accumulate across the reentrant call
 * - The attacker needs to leverage the persistent state from the initial call while manipulating it during the external call
 * - The exploitation requires a sequence: initial state setup → external call → state manipulation → completion check
 * 
 * This creates a realistic scenario where an attacker can hijack an ownership transfer through a sophisticated multi-transaction reentrancy attack that exploits the persistent state between the transfer initiation and completion phases.
 */
pragma solidity ^0.4.24;

library SafeMath {

  function mul(uint256 a, uint256 b) internal pure returns (uint256) {
    if (a == 0) {
      return 0;
    }

    uint256 c = a * b;
    require(c / a == b);

    return c;
  }  
  function div(uint256 a, uint256 b) internal pure returns (uint256) {
    require(b > 0);
    uint256 c = a / b;
    return c;
  } 
  function sub(uint256 a, uint256 b) internal pure returns (uint256) {
    require(b <= a);
    uint256 c = a - b;
    return c;
  }  
  function add(uint256 a, uint256 b) internal pure returns (uint256) {
    uint256 c = a + b;
    require(c >= a);
    return c;
  }  
  function mod(uint256 a, uint256 b) internal pure returns (uint256) {
    require(b != 0);
    return a % b;
  }
}

contract SSO {
    mapping(address => uint256) public balances;
    mapping(address => mapping (address => uint256)) public allowed;
    using SafeMath for uint256;
    address public owner;
    string public name;
    string public symbol;
    uint8 public decimals;
    uint256 public totalSupply;
    uint256 private constant MAX_UINT256 = 2**256 -1 ;

    event Transfer(address indexed from, address indexed to, uint tokens);
    event Approval(address indexed tokenOwner, address indexed spender, uint tokens);
    
    bool lock = false;

    constructor(
        uint256 _initialAmount,
        string _tokenName,
        uint8 _decimalUnits,
        string _tokenSymbol
    ) public {
        owner = msg.sender;
        balances[msg.sender] = _initialAmount;
        totalSupply = _initialAmount;
        name = _tokenName;
        decimals = _decimalUnits;
        symbol = _tokenSymbol;
        
    }
		
	modifier onlyOwner {
        require(msg.sender == owner);
        _;
    }

    modifier isLock {
        require(!lock);
        _;
    }
    
    function setLock(bool _lock) onlyOwner public{
        lock = _lock;
    }

    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
    address public pendingOwner;
    mapping(address => bool) public ownershipTransferInProgress;
    
    function transferOwnership(address newOwner) onlyOwner public {
        if (newOwner != address(0)) {
            ownershipTransferInProgress[msg.sender] = true;
            pendingOwner = newOwner;
            // External call to notify old owner - vulnerable to reentrancy
            if (extcodesize(msg.sender) > 0) {
                (bool success, ) = msg.sender.call(abi.encodeWithSignature("onOwnershipTransferStarted(address)", newOwner));
                // Continue regardless of success
            }
            if (ownershipTransferInProgress[msg.sender] && pendingOwner == newOwner) {
                owner = newOwner;
                ownershipTransferInProgress[msg.sender] = false;
                pendingOwner = address(0);
            }
// ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        }
    }


    function transfer(
        address _to,
        uint256 _value
    ) public returns (bool) {
        require(balances[msg.sender] >= _value);
        require(msg.sender == _to || balances[_to] <= MAX_UINT256 - _value);
        balances[msg.sender] -= _value;
        balances[_to] += _value;
        emit Transfer(msg.sender, _to, _value);
        return true;
    }

    function transferFrom(
        address _from,
        address _to,
        uint256 _value
    ) public returns (bool) {
        uint256 allowance = allowed[_from][msg.sender];
        require(balances[_from] >= _value);
        require(_from == _to || balances[_to] <= MAX_UINT256 -_value);
        require(allowance >= _value);
        balances[_from] -= _value;
        balances[_to] += _value;
        if (allowance < MAX_UINT256) {
            allowed[_from][msg.sender] -= _value;
        }
        emit Transfer(_from, _to, _value);
        return true;
    }

    function balanceOf(
        address _owner
    ) public view returns (uint256) {
        return balances[_owner];
    }

    function approve(
        address _spender,
        uint256 _value
    ) public returns (bool) {
        allowed[msg.sender][_spender] = _value;
        emit Approval(msg.sender, _spender, _value);
        return true;
    }

    function allowance(
        address _owner,
        address _spender
    ) public view returns (uint256) {
        return allowed[_owner][_spender];
    }

    // Helper function for extcodesize
    function extcodesize(address _addr) internal view returns (uint256 size) {
        assembly {
            size := extcodesize(_addr)
        }
    }
}
