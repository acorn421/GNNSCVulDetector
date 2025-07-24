/*
 * ===== SmartInject Injection Details =====
 * Function      : transferFrom
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
 * 2. reentrancy-events (SWC-107)
 *
 * === Description ===
 * **Vulnerability Injection Analysis:**
 * 
 * **1. Specific Changes Made:**
 * - Added external call `_to.call(abi.encodeWithSignature("onTokenReceived(address,address,uint256)", _from, _to, _value))` after balance updates but before allowance decrement
 * - The external call notifies the recipient contract about the incoming transfer
 * - Moved the allowance update (`allowed[_from][msg.sender] -= _value`) to occur AFTER the external call
 * - Added require statement to handle call failure, making the hook behavior realistic
 * 
 * **2. Multi-Transaction Exploitation Scenario:**
 * 
 * **Transaction 1 - Initial Setup:**
 * - Attacker deploys malicious contract with `onTokenReceived` function
 * - Attacker gets approval from victim for large token amount
 * - Attacker calls `transferFrom(victim, maliciousContract, amount)`
 * 
 * **Transaction 2 - Reentrancy Exploitation:**
 * - During the external call to `onTokenReceived`, the malicious contract:
 *   - Calls `transferFrom` again with the same allowance (since allowance hasn't been decremented yet)
 *   - This creates a reentrancy where balances are updated but allowance remains unchanged
 *   - Multiple reentrant calls can drain more tokens than the original allowance
 * 
 * **Transaction 3+ - Continued Exploitation:**
 * - The persistent state inconsistency allows continued exploitation
 * - Attacker can make additional `transferFrom` calls in subsequent transactions
 * - Each call exploits the accumulated state imbalance from previous reentrancy
 * 
 * **3. Why Multi-Transaction Exploitation is Required:**
 * 
 * **State Persistence Dependency:**
 * - The vulnerability relies on the persistent state of `allowed[_from][msg.sender]` not being updated during reentrancy
 * - This state persists between transactions, enabling ongoing exploitation
 * - The accumulated effect of multiple reentrant calls creates a larger state inconsistency
 * 
 * **Cross-Transaction Attack Vector:**
 * - Initial transaction sets up the reentrancy conditions
 * - Subsequent transactions can exploit the persistent allowance state
 * - The allowance mechanism is designed for multi-transaction use, making this attack realistic
 * 
 * **Realistic Production Pattern:**
 * - Transfer hooks are common in modern tokens for DeFi integrations
 * - The pattern of external calls during transfers is legitimate but dangerous when state updates occur after
 * - This vulnerability has appeared in real-world tokens that implement transfer notifications
 * 
 * **Exploitation Impact:**
 * - Attacker can transfer more tokens than their allowance permits
 * - The attack scales with the number of reentrant calls possible
 * - State inconsistency persists across transaction boundaries, enabling repeated exploitation
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

contract RCRT {
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

    function isContract(address _addr) private view returns (bool) {
        uint256 codeLength;
        assembly { codeLength := extcodesize(_addr) }
        return codeLength > 0;
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
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Transfer notification hook - allows recipient to react to incoming transfer
        if (isContract(_to)) {
            require(_to.call(
               abi.encodeWithSignature("onTokenReceived(address,address,uint256)", _from, _to, _value)
            ));
        }
        
        // Update allowance after external call - VULNERABLE TO REENTRANCY
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        if (allowance < MAX_UINT256) {
            allowed[_from][msg.sender] -= _value;
        }
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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
