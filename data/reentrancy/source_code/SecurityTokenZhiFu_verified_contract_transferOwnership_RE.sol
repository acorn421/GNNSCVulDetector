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
 * Modified the transferOwnership function to introduce a stateful, multi-transaction reentrancy vulnerability by adding an external call to the newOwner address before updating the owner state. This creates a window where the ownership state can be manipulated across multiple transactions.
 * 
 * **Specific Changes Made:**
 * 1. Added an external call to `newOwner.call()` with `onOwnershipTransferred(address)` signature
 * 2. Placed the external call BEFORE the state update (`owner = newOwner`)
 * 3. Added a check for contract code existence to make the callback realistic
 * 4. Preserved the original function logic and signature
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 1. **Transaction 1**: Attacker deploys a malicious contract that implements `onOwnershipTransferred()`
 * 2. **Transaction 2**: Current owner calls `transferOwnership(maliciousContract)` 
 * 3. **During Transaction 2**: The malicious contract's `onOwnershipTransferred()` callback is triggered while `owner` is still the old owner
 * 4. **Reentrancy Attack**: The malicious contract calls `transferOwnership(attackerAddress)` again during the callback
 * 5. **State Manipulation**: Since `owner` hasn't been updated yet, the `onlyOwner` modifier passes, allowing the attacker to change ownership to their desired address
 * 6. **Final State**: The attacker gains control of the contract through this multi-step process
 * 
 * **Why Multi-Transaction is Required:**
 * - The vulnerability requires deploying a malicious contract first (Transaction 1)
 * - The actual exploitation happens during the ownership transfer call (Transaction 2)
 * - The reentrancy attack depends on the persistent state of the `owner` variable across the call stack
 * - The exploit leverages the time window between the external call and state update, which persists across the transaction execution
 * - Multiple actors (original owner, attacker contract, final attacker address) are involved in the exploitation sequence
 * 
 * This creates a realistic, stateful vulnerability that requires careful orchestration across multiple transactions and depends on the persistent contract state.
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

contract SecurityTokenZhiFu {
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

    function transferOwnership(address newOwner) onlyOwner public {
        if (newOwner != address(0)) {
            // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
            // External call before state change - vulnerable to reentrancy
            if (extcodesize(newOwner) > 0) {
                // Inline assembly to call extcodesize
                newOwner.call(
                    abi.encodeWithSignature("onOwnershipTransferred(address)", owner)
                );
                // Continue regardless of success to maintain functionality
            }
            // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
            owner = newOwner;
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
    
    // Helper: extcodesize implementation for Solidity 0.4.x
    function extcodesize(address _addr) internal view returns (uint256 _size) {
        assembly { _size := extcodesize(_addr) }
    }
}
