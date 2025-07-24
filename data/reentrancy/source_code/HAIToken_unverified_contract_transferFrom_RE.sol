/*
 * ===== SmartInject Injection Details =====
 * Function      : transferFrom
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
 * Introduced a STATEFUL, MULTI-TRANSACTION reentrancy vulnerability by:
 * 
 * 1. **Added External Call**: Introduced a call to recipient contract's `onTokenReceived` function before state updates
 * 2. **Moved State Update**: The critical `allowance` decrement now happens AFTER the external call, creating a reentrancy window
 * 3. **Checks-Effects-Interactions Violation**: The function now violates the secure pattern by performing external interactions before updating internal state
 * 
 * **Multi-Transaction Exploitation Pattern:**
 * 
 * **Transaction 1 (Setup):**
 * - User approves allowance for attacker contract
 * - Attacker calls transferFrom with malicious recipient contract
 * 
 * **Transaction 2 (Primary Attack):**
 * - transferFrom is called, external call triggers malicious recipient
 * - During the external call, the allowance hasn't been decremented yet
 * - Malicious recipient can call transferFrom again with the same allowance
 * 
 * **Transaction 3+ (Continued Exploitation):**
 * - The inconsistent state persists between transactions
 * - Attacker can drain funds by repeatedly calling transferFrom
 * - Each call exploits the window where allowance check passes but decrement happens after external call
 * 
 * **Why Multi-Transaction:**
 * - The vulnerability requires the attacker to have a contract deployed that can receive the callback
 * - State changes (allowance) persist between transactions, enabling continued exploitation
 * - The attack requires setting up allowances in previous transactions
 * - Full exploitation requires multiple transferFrom calls to drain maximum funds
 * 
 * **Exploitation Scenario:**
 * 1. Attacker deploys malicious contract with onTokenReceived function
 * 2. Victim approves large allowance for attacker
 * 3. Attacker calls transferFrom with their malicious contract as recipient
 * 4. During callback, malicious contract calls transferFrom again before allowance is decremented
 * 5. Process repeats across multiple transactions to drain funds
 * 
 * The vulnerability is realistic as it mimics ERC777 callback patterns and could easily be introduced during token upgrade implementations.
 */
pragma solidity ^0.4.24;

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
    // assert(b > 0); // Solidity automatically throws when dividing by 0
    uint256 c = a / b;
    // assert(a == b * c + a % b); // There is no case in which this doesn't hold
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

contract HAIToken {
    
    using SafeMath for uint256;
    
    string public name = "HAI";      //  token name
    
    string public symbol = "HAI";           //  token symbol
    
    uint256 public decimals = 8;            //  token digit

    mapping (address => uint256) public balanceOf;
    
    mapping (address => mapping (address => uint256)) public allowance;
 
    
    uint256 public totalSupply = 0;

    uint256 constant valueFounder = 10000000000000000;
    
    

    modifier validAddress {
        assert(0x0 != msg.sender);
        _;
    }
    
    event Transfer(address indexed _from, address indexed _to, uint256 _value);
    
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);

    constructor() public {

        totalSupply = valueFounder;
        balanceOf[msg.sender] = valueFounder;
        emit Transfer(0x0, msg.sender, valueFounder);
    }
    
    function _transfer(address _from, address _to, uint256 _value) private {
        require(_to != 0x0);
        require(balanceOf[_from] >= _value);
        balanceOf[_from] = balanceOf[_from].sub(_value);
        balanceOf[_to] = balanceOf[_to].add(_value);
        emit Transfer(_from, _to, _value);
    }
    
    function transfer(address _to, uint256 _value) validAddress public returns (bool success) {
        _transfer(msg.sender, _to, _value);
        return true;
    }

    function isContract(address _addr) internal view returns (bool) {
        uint256 length;
        assembly { length := extcodesize(_addr) }
        return length > 0;
    }

    function transferFrom(address _from, address _to, uint256 _value) validAddress public returns (bool success) {
        require(_value <= allowance[_from][msg.sender]);
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Add external call to recipient before state updates (if recipient is a contract)
        if (isContract(_to)) {
            // Call recipient contract's onTokenReceived function
            (bool callSuccess,) = _to.call(
                abi.encodeWithSignature("onTokenReceived(address,address,uint256)", _from, _to, _value)
            );
            // Continue execution regardless of call result for compatibility
        }
        
        // State update moved AFTER external call - creates reentrancy window
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        allowance[_from][msg.sender] = allowance[_from][msg.sender].sub(_value);
        _transfer(_from, _to, _value);
        return true;
    }

    function approve(address _spender, uint256 _value) validAddress public returns (bool success) {
        require(balanceOf[msg.sender] >= _value);
        allowance[msg.sender][_spender] = _value;
        emit Approval(msg.sender, _spender, _value);
        return true;
    }
}
