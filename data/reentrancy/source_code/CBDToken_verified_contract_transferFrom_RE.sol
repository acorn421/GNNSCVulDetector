/*
 * ===== SmartInject Injection Details =====
 * Function      : transferFrom
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 3 findings
 * Total Found   : 4 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-benign (SWC-107)
 * 3. reentrancy-events (SWC-107)
 *
 * === Description ===
 * This vulnerability introduces a stateful, multi-transaction reentrancy attack through the following mechanisms:
 * 
 * **1. Specific Code Changes:**
 * - Added external call to recipient contract (`_to.call(...)`) before allowance state updates
 * - Introduced pending transfers tracking using storage mapping
 * - Moved allowance decrementation to occur AFTER the external call
 * - Added conditional logic for partial transfers that maintains state between transactions
 * 
 * **2. Multi-Transaction Exploitation Pattern:**
 * - **Transaction 1**: Attacker calls transferFrom, triggering external call to malicious contract
 * - **During callback**: Malicious contract cannot immediately re-enter due to allowance check, but can set up state for future exploitation
 * - **Transaction 2**: With partially updated allowance state persisting from Transaction 1, attacker can exploit the inconsistent state
 * - **Transaction 3+**: Continued exploitation through accumulated state manipulation across multiple calls
 * 
 * **3. Why Multi-Transaction Exploitation is Required:**
 * - The vulnerability relies on the `pendingTransfers` state persisting between transactions
 * - Single-transaction reentrancy is blocked by the allowance check, but multi-transaction exploitation works because:
 *   - State updates occur after external calls, creating temporal inconsistency
 *   - Partial transfer logic maintains exploitable state across transaction boundaries
 *   - The external call provides the entry point for setting up multi-transaction attack sequences
 * 
 * **Exploitation Scenario:**
 * 1. Attacker approves themselves a large allowance
 * 2. Calls transferFrom with partial amount, triggering callback
 * 3. Callback contract records the current state and prepares for next transaction
 * 4. In subsequent transactions, attacker exploits the accumulated pending transfer state
 * 5. Can drain funds by repeatedly exploiting the state inconsistency across multiple transactions
 * 
 * This creates a realistic, stateful vulnerability that requires multiple transactions to fully exploit, making it much more difficult to detect with single-transaction analysis tools.
 */
/**
 *Submitted for verification at Etherscan.io on 2018-08-28
*/

pragma solidity ^0.4.11;

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

contract CBDToken {
    
    using SafeMath for uint256;
    
    string public name = "CBD";      //  token name
    
    string public symbol = "CBD";           //  token symbol
    
    uint256 public decimals = 8;            //  token digit

    mapping (address => uint256) public balanceOf;
    
    mapping (address => mapping (address => uint256)) public allowance;
    
    uint256 public totalSupply = 0;
    uint256 constant valueFounder = 200000000000000000;
    
    address owner = 0x0;
    
    address operator = 0x0;

    modifier isOwner {
        assert(owner == msg.sender);
        _;
    }
    
    modifier isOperator {
        assert(operator == msg.sender);
        _;
    }

    modifier validAddress {
        assert(0x0 != msg.sender);
        _;
    }
    
    event Transfer(address indexed _from, address indexed _to, uint256 _value);
    
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);
    
    event Burn(address indexed from, uint256 value);

    function CBDToken() public {
        owner = msg.sender;
        operator = msg.sender;
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

    function transferFrom(address _from, address _to, uint256 _value) validAddress public returns (bool success) {
        require(_value <= allowance[_from][msg.sender]);
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Add pending transfers tracking for multi-transaction exploitation
        // mapping(address => mapping(address => uint256)) storage pendingTransfers = allowance;
        uint256 pendingAmount = allowance[_from][msg.sender];
        
        // External call to recipient before state updates (reentrancy entry point)
        uint size;
        assembly { size := extcodesize(_to) }
        if (size > 0) {
            // Note: No .code property in <=0.4.x; use extcodesize(_to)
            _to.call(abi.encodeWithSignature("onTokenTransfer(address,address,uint256)", _from, _to, _value));
            // Continue regardless of callback success
        }
        
        // Critical vulnerability: State update occurs after external call
        // This creates a window where allowance is not yet decremented
        allowance[_from][msg.sender] = allowance[_from][msg.sender].sub(_value);
        
        // If this is a partial transfer (less than full allowance), mark as pending
        if (_value < pendingAmount) {
            // This state persists between transactions, enabling multi-transaction exploitation
            allowance[_from][msg.sender] = pendingAmount.sub(_value);
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        _transfer(_from, _to, _value);
        return true;
    }

    function approve(address _spender, uint256 _value) validAddress public returns (bool success) {
        require(balanceOf[msg.sender] >= _value);
        allowance[msg.sender][_spender] = _value;
        emit Approval(msg.sender, _spender, _value);
        return true;
    }
    
    function burn(uint256 _value) validAddress public  returns (bool success) {
        require(balanceOf[msg.sender] >= _value);   // Check if the sender has enough
        balanceOf[msg.sender] = balanceOf[msg.sender].sub(_value);            // Subtract from the sender
        totalSupply = totalSupply.sub(_value);                      // Updates totalSupply
        emit Burn(msg.sender, _value);
        emit Transfer(msg.sender, 0x0, _value);
        return true;
    }

  

    
    function setOperator(address addr) validAddress isOwner public {
        operator = addr;
    }
    
}
