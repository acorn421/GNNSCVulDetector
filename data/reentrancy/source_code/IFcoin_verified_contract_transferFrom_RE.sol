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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to `ITokenReceiver(_to).onTokenReceived(_from, _value)` AFTER updating balances but BEFORE updating allowances. This creates a critical time window where:
 * 
 * 1. **State Setup (Transaction 1)**: An attacker first needs to set up allowances using the `approve` function to authorize themselves or a malicious contract to spend tokens.
 * 
 * 2. **Multi-Transaction Exploitation**: The vulnerability requires multiple transactions to exploit:
 *    - **Transaction 1**: Attacker calls `transferFrom`, which updates balances and triggers the external call
 *    - **During the external call**: The malicious recipient contract can call `transferFrom` again with the same allowance (since it hasn't been decremented yet)
 *    - **Transaction 2+**: Additional recursive calls can drain more tokens than the original allowance permits
 * 
 * 3. **Stateful Nature**: The vulnerability depends on:
 *    - Pre-existing allowance state set up in previous transactions
 *    - The specific order of state updates (balances first, allowances second)
 *    - The persistent allowance state that enables multiple calls
 * 
 * 4. **Multi-Transaction Requirement**: This cannot be exploited in a single transaction because:
 *    - The attacker must first obtain allowances through separate `approve` calls
 *    - The reentrancy attack requires the external contract to be deployed and configured
 *    - The exploitation occurs across multiple nested calls that span transaction boundaries
 * 
 * The vulnerability violates the Checks-Effects-Interactions pattern by performing an external call between critical state updates, creating a window where the contract state is inconsistent and can be exploited through cross-transaction reentrancy.
 */
pragma solidity ^0.4.11;

/**
 * @title SafeMath
 * @dev Math operations with safety checks that throw on error
 */
library SafeMath {
  function mul(uint256 a, uint256 b) internal returns (uint256) {
    if (a == 0) {
      return 0;
    }
    uint256 c = a * b;
    assert(c / a == b);
    return c;
  }

  function div(uint256 a, uint256 b) internal returns (uint256) {
    // assert(b > 0); // Solidity automatically throws when dividing by 0
    uint256 c = a / b;
    // assert(a == b * c + a % b); // There is no case in which this doesn't hold
    return c;
  }

  function sub(uint256 a, uint256 b) internal returns (uint256) {
    assert(b <= a);
    return a - b;
  }

  function add(uint256 a, uint256 b) internal returns (uint256) {
    uint256 c = a + b;
    assert(c >= a);
    return c;
  }
}

// Minimal interface for the reentrancy notification
interface ITokenReceiver {
    function onTokenReceived(address _from, uint256 _value) external;
}

contract IFcoin {
    
    uint private constant _totalSupply = 2500000000000000000000000;
 
    using SafeMath for uint256;
 
    string public constant symbol = "IFC";
    string public constant name = "IFcoin";
    uint8 public constant decimals = 18;
    
    mapping(address => uint256) balances;
    mapping(address => mapping(address => uint256)) allowed;
    
    constructor() public {
        balances[msg.sender] = _totalSupply;
    }
 
    function totalSupply() public constant returns (uint256) {
        return _totalSupply;
    }
 
    function balanceOf(address _owner) public constant returns (uint256 balance) {
        return balances[_owner];
    }
    
    function transfer(address _to, uint256 _value) public returns (bool success) {
        require(
            balances[msg.sender] >= _value
            && _value > 0 
            );
            balances[msg.sender] -= _value;
            balances[_to] += _value;
            Transfer(msg.sender, _to, _value);
            return true;
    }
    
    function transferFrom(address _from, address _to, uint _value) public returns (bool success) {
        require(
            allowed[_from][msg.sender] >= _value
            && balances[_from] >= _value
            && _value > 0 
        );
        balances[_from] -= _value;
        balances[_to] += _value;
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // Notify recipient contract about incoming transfer
        if (isContract(_to)) {
            ITokenReceiver(_to).onTokenReceived(_from, _value);
        }
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        allowed[_from][msg.sender] -= _value;
        Transfer(_from, _to, _value);
        return true;
    }
    
    function approve(address _spender, uint256 _value) public returns (bool success) {
        allowed[msg.sender][_spender] = _value;
        Approval(msg.sender, _spender, _value);
        return true;
    }
    
    function allowance(address _owner, address _spender) public constant returns (uint256 remaining) {
        return allowed[_owner][_spender];
    } 
    
    // Helper to emulate _to.code.length in old Solidity
    function isContract(address _addr) internal view returns (bool) {
        uint256 size;
        assembly {
            size := extcodesize(_addr)
        }
        return size > 0;
    }
    
    event Transfer(address indexed _from, address indexed _to, uint256 _value);
    event Approval(address indexed _owner,address indexed _spender, uint256 _value);
    
}
