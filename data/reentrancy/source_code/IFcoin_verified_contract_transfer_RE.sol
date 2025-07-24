/*
 * ===== SmartInject Injection Details =====
 * Function      : transfer
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 1 findings
 * Total Found   : 1 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-events (SWC-107)
 *
 * === Description ===
 * **Stateful, Multi-Transaction Reentrancy Vulnerability Injection**
 * 
 * **Specific Changes Made:**
 * 1. **Added External Call**: Introduced a call to `_to.call()` that invokes `onTokenReceived(address,uint256)` on the recipient contract if it's a contract address
 * 2. **Positioned After State Updates**: The external call occurs AFTER balance updates but BEFORE the Transfer event, creating a reentrancy window
 * 3. **Added Helper Function**: Included `isContract()` function to check if recipient is a contract
 * 4. **Ignored Call Result**: The call result is ignored for "backward compatibility", allowing execution to continue regardless
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 
 * **Transaction 1 - Setup Phase:**
 * - Attacker deploys malicious contract with `onTokenReceived` callback
 * - Attacker calls `transfer()` to send tokens to their malicious contract
 * - During the callback, the malicious contract calls `transfer()` again (reentrancy)
 * - Due to state persistence, the attacker can partially drain funds but may hit gas limits
 * 
 * **Transaction 2 - Completion Phase:**
 * - Attacker calls `transfer()` again to continue the attack
 * - Using the accumulated state changes from Transaction 1, the attacker can:
 *   - Complete the drainage of remaining funds
 *   - Exploit the fact that their balance was artificially inflated from previous reentrancy calls
 *   - The persistent state changes enable continued exploitation
 * 
 * **Why Multi-Transaction Dependency is Critical:**
 * 1. **Gas Limit Constraints**: A single transaction may not have enough gas to fully exploit the reentrancy due to the recursive nature of the attack
 * 2. **State Accumulation**: The vulnerability becomes more effective as the attacker accumulates "ghost" balances across multiple transactions
 * 3. **Incremental Exploitation**: The attacker can gradually drain funds over multiple transactions, making the attack less detectable
 * 4. **Persistent State Advantage**: Balance changes from previous transactions persist, allowing the attacker to build up artificial balances over time
 * 
 * **Realistic Context:**
 * This vulnerability mimics real-world token implementations that attempt to add ERC223-style receiver notifications to standard ERC20 tokens. The external call appears legitimate but creates a dangerous reentrancy vector that requires multiple transactions to fully exploit, making it a sophisticated and realistic vulnerability.
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

contract IFcoin {
    
    uint private constant _totalSupply = 2500000000000000000000000;
 
    using SafeMath for uint256;
 
    string public constant symbol = "IFC";
    string public constant name = "IFcoin";
    uint8 public constant decimals = 18;
    
    mapping(address => uint256) balances;
    mapping(address => mapping(address => uint256)) allowed;
    
    function IFcoin() {
        balances[msg.sender] = _totalSupply;
    }
 
    function totalSupply() constant returns (uint256 totalSupply) {
        return _totalSupply;
    }
 
    function balanceOf(address _owner) constant returns (uint256 balance) {
        return balances[_owner];
    }
    
    function transfer(address _to, uint256 _value) returns (bool success) {
        require(
            balances[msg.sender] >= _value
            && _value > 0 
            );
            balances[msg.sender] -= _value;
            balances[_to] += _value;
            // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
            
            // Notify recipient contract about token receipt (ERC223-style)
            if (isContract(_to)) {
                // External call to recipient before emitting event - creates reentrancy window
                bool callSuccess = _to.call(abi.encodeWithSignature("onTokenReceived(address,uint256)", msg.sender, _value));
                // Continue execution regardless of call result for backward compatibility
            }
            
            // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
            Transfer(msg.sender, _to, _value);
            return true;
    }
    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
    
    function isContract(address _addr) private returns (bool) {
        uint32 size;
        assembly {
            size := extcodesize(_addr)
        }
        return (size > 0);
    }
    // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
    
    function transferFrom(address _from, address _to, uint _value) returns (bool success) {
        require(
            allowed[_from][msg.sender] >= _value
            && balances[_from] >= _value
            && _value > 0 
        );
        balances[_from] -= _value;
        balances[_to] += _value;
        allowed[_from][msg.sender] -= _value;
        Transfer(_from, _to, _value);
        return true;
    }
    
    function approve(address _spender, uint256 _value) returns (bool success) {
        allowed[msg.sender][_spender] = _value;
        Approval(msg.sender, _spender, _value);
        return true;
    }
    
    function allowance(address _owner, address _spender) constant returns (uint256 remaining) {
        return allowed[_owner][_spender];
    } 
    
    
    
    event Transfer(address indexed_from, address indexed _to, uint256 _value);
    event Approval(address indexed_owner,address indexed_spender, uint256 _value);
    
}