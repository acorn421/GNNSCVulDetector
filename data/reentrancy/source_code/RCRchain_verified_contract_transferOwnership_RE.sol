/*
 * ===== SmartInject Injection Details =====
 * Function      : transferOwnership
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 2 findings
 * Total Found   : 2 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-benign (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by:
 * 
 * 1. **Added State Variable**: Introduced `pendingOwnershipTransfers` mapping to track pending ownership transfers across transactions.
 * 
 * 2. **External Call Before State Update**: Added an external call to `IOwnable(newOwner).onOwnershipTransferred()` before updating the owner state, violating the Checks-Effects-Interactions pattern.
 * 
 * 3. **Stateful Vulnerability**: The vulnerability requires multiple transactions to exploit:
 *    - **Transaction 1**: Attacker calls `transferOwnership(maliciousContract)` 
 *    - **During External Call**: The malicious contract's `onOwnershipTransferred` callback can:
 *      - Re-enter `transferOwnership` with a different address while `pendingOwnershipTransfers[maliciousContract] = true`
 *      - Call other privileged functions while still being recognized as the pending owner
 *      - Manipulate contract state before the original ownership transfer completes
 *    - **Transaction 2**: The attacker can exploit the inconsistent state where multiple addresses may be marked as pending owners
 * 
 * 4. **Multi-Transaction Exploitation**: The vulnerability cannot be exploited in a single transaction because:
 *    - The external call creates a window where the contract state is inconsistent
 *    - The `pendingOwnershipTransfers` mapping persists between transactions
 *    - An attacker needs separate transactions to fully exploit the race condition between pending and actual ownership states
 * 
 * 5. **Realistic Implementation**: The code appears to implement a legitimate ownership notification system but introduces a classic reentrancy vulnerability through improper state management and external call ordering.
 */
pragma solidity ^0.4.25;


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
    require(b > 0); // Solidity only automatically asserts when dividing by 0
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

// Added interface declaration for IOwnable
interface IOwnable {
    function onOwnershipTransferred(address previousOwner, address newOwner) external;
}

contract RCRchain {
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
    mapping(address => bool) private pendingOwnershipTransfers;
    
    function transferOwnership(address newOwner) onlyOwner public {
        if (newOwner != address(0)) {
            // Mark ownership transfer as pending
            pendingOwnershipTransfers[newOwner] = true;

            // Notify the new owner about the pending transfer
            // This external call creates a reentrancy vulnerability
            IOwnable(newOwner).onOwnershipTransferred(owner, newOwner);
            // Complete the transfer
            if (pendingOwnershipTransfers[newOwner]) {
                owner = newOwner;
                pendingOwnershipTransfers[newOwner] = false;
            }
        }
    }
// ===== SMARTINJECT: Reentrancy VULNERABILITY END =====

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
}
