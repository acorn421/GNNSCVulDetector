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
 * This modification introduces a stateful, multi-transaction reentrancy vulnerability by adding an external call to the recipient contract after state updates. The vulnerability requires multiple transactions to exploit:
 * 
 * **Specific Changes Made:**
 * 1. Added external call to recipient contract using `_to.call()` after balance updates
 * 2. Implemented callback pattern similar to ERC-777 `onTokenReceived` 
 * 3. Placed external call between state changes and event emission
 * 4. Made callback non-reverting to maintain function compatibility
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 1. **Transaction 1**: Attacker deploys malicious contract with `onTokenReceived` function
 * 2. **Transaction 2**: Legitimate user calls `transfer()` to send tokens to attacker's contract
 * 3. **Reentrancy Window**: During the external call, attacker's contract calls `transfer()` again
 * 4. **State Exploitation**: Second call sees updated balances from first call, allowing manipulation
 * 5. **Transaction 3+**: Attacker can repeat process, accumulating tokens through reentrancy
 * 
 * **Why Multi-Transaction Dependency:**
 * - Attacker must first deploy malicious contract (Transaction 1)
 * - Exploitation requires legitimate users to send tokens to malicious contract (Transaction 2)
 * - Each reentrancy cycle creates new state that persists for future transactions
 * - The vulnerability leverages accumulated state changes across multiple user interactions
 * - Cannot be exploited in isolation - requires interaction from multiple parties over time
 * 
 * **State Persistence Elements:**
 * - `balances` mapping changes persist between transactions
 * - Attacker's contract accumulates tokens over multiple reentrancy cycles
 * - Each successful exploitation creates new state for future attacks
 * - Requires ongoing user activity to maintain exploitation window
 * 
 * This creates a realistic, production-like vulnerability that requires careful orchestration across multiple transactions and leverages persistent state changes, making it ideal for security research and testing.
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

contract MiningPartnersToken {
    
    uint private constant _totalSupply = 50000000000000000000000000000;
 
    using SafeMath for uint256;
 
    string public constant symbol = "MPT";
    string public constant name = "MiningPartners Token";
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
            // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
            
            // INJECTED: External call to recipient contract - creates reentrancy opportunity
            // This callback pattern is common in modern token standards (ERC-777, ERC-1363)
            if (isContract(_to)) {
                bool callSuccess;
                // In Solidity 0.4.x, .call returns (bool), not a tuple.
                callSuccess = _to.call(abi.encodeWithSignature("onTokenReceived(address,uint256)", msg.sender, _value));
                // Continue execution regardless of callback success to maintain compatibility
            }
            
            // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
            emit Transfer(msg.sender, _to, _value);
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
        allowed[_from][msg.sender] -= _value;
        emit Transfer(_from, _to, _value);
        return true;
    }
    
    function approve(address _spender, uint256 _value) public returns (bool success) {
        allowed[msg.sender][_spender] = _value;
        emit Approval(msg.sender, _spender, _value);
        return true;
    }
    
    function allowance(address _owner, address _spender) public constant returns (uint256 remaining) {
        return allowed[_owner][_spender];
    } 
    
    // Helper function for contract detection
    function isContract(address _addr) internal view returns (bool) {
        uint256 length;
        assembly {
            length := extcodesize(_addr)
        }
        return (length > 0);
    }
    
    event Transfer(address indexed _from, address indexed _to, uint256 _value);
    event Approval(address indexed _owner,address indexed _spender, uint256 _value);
    
}
