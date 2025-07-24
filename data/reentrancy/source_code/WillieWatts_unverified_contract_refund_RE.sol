/*
 * ===== SmartInject Injection Details =====
 * Function      : refund
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
 * This injection creates a stateful, multi-transaction reentrancy vulnerability by:
 * 
 * 1. **Adding State Variables**: Two new mappings track refund progress and pending amounts across transactions
 * 2. **Creating Reentrancy Window**: The external call (msg.sender.send) occurs before state cleanup, allowing callbacks to manipulate pendingRefunds
 * 3. **Enabling State Accumulation**: During reentrancy, pendingRefunds accumulates additional values while the original balance deduction hasn't occurred yet
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * - **Transaction 1**: User calls refund(100) → refundInProgress[user] = true, pendingRefunds[user] = 100
 * - **Reentrancy Callback**: User's contract receives ether, immediately calls refund(50) again
 * - **Still in Transaction 1**: refundInProgress[user] is true, so pendingRefunds[user] += 50 (now 150)
 * - **Continued Reentrancy**: User can call refund multiple times, each accumulating to pendingRefunds
 * - **Transaction 2**: If the attack is sophisticated, user can trigger additional refunds in subsequent transactions while the state is inconsistent
 * 
 * **Why Multi-Transaction Required:**
 * - The vulnerability requires the attacker to have a contract that can receive ether and make callbacks
 * - State accumulation in pendingRefunds persists across the reentrancy calls
 * - The refundInProgress flag creates a stateful condition that affects behavior across multiple calls
 * - Maximum exploitation requires coordinated sequence of calls with state manipulation between them
 * 
 * **Key Vulnerability Points:**
 * - External call before state reset creates reentrancy window
 * - pendingRefunds accumulation during reentrancy allows inflated refund tracking
 * - Balance deduction occurs with original _value while pendingRefunds may be inflated
 * - State flags persist across multiple calls within the same transaction and can be manipulated
 */
pragma solidity ^0.4.6;

contract tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData); }


contract WillieWatts {

    string public standard = 'Token 0.1';
    string public name;
    string public symbol;
    uint8 public decimals;
    uint256 public totalSupply;

    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;

    event Transfer(address indexed from, address indexed to, uint256 value);

    function WillieWatts(
        string tokenName,
        string tokenSymbol
        ) {              
        totalSupply = 0;                        
        name = tokenName;   
        symbol = tokenSymbol;   
        decimals = 0;  
    }


    /* Send coins */
    function transfer(address _to, uint256 _value) {
        if (balanceOf[msg.sender] < _value) throw;          
        if (balanceOf[_to] + _value < balanceOf[_to]) throw; 
        balanceOf[msg.sender] -= _value;                 
        balanceOf[_to] += _value;                    
        Transfer(msg.sender, _to, _value);             
    }


    function approve(address _spender, uint256 _value)
        returns (bool success) {
        allowance[msg.sender][_spender] = _value;
        return true;
    }


    function approveAndCall(address _spender, uint256 _value, bytes _extraData)
        returns (bool success) {
        tokenRecipient spender = tokenRecipient(_spender);
        if (approve(_spender, _value)) {
            spender.receiveApproval(msg.sender, _value, this, _extraData);
            return true;
        }
    }        

    /* A contract attempts to get the coins */
    function transferFrom(address _from, address _to, uint256 _value) returns (bool success) {
        if (balanceOf[_from] < _value) throw;                 // Check if the sender has enough
        if (balanceOf[_to] + _value < balanceOf[_to]) throw;  // Check for overflows
        if (_value > allowance[_from][msg.sender]) throw;   // Check allowance
        balanceOf[_from] -= _value;                          // Subtract from the sender
        balanceOf[_to] += _value;                            // Add the same to the recipient
        allowance[_from][msg.sender] -= _value;
        Transfer(_from, _to, _value);
        return true;
    }

    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
mapping (address => uint256) public pendingRefunds;
    mapping (address => bool) public refundInProgress;
    
    function refund(uint256 _value) returns (bool success) {
// ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
      uint256 etherValue = (_value * 1 ether) / 1000;

      if(balanceOf[msg.sender] < _value) throw;   
      // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
      
      // Track refund in progress and accumulate pending refunds
      if(!refundInProgress[msg.sender]) {
          refundInProgress[msg.sender] = true;
          pendingRefunds[msg.sender] = _value;
      } else {
          // Allow accumulation of refunds during reentrancy
          pendingRefunds[msg.sender] += _value;
      }
      
      // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
      if(!msg.sender.send(etherValue)) throw;
      
      // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
      // Only deduct balance after successful send, but use original _value
      // This creates a window where pendingRefunds can be manipulated
      // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
      balanceOf[msg.sender] -= _value;
      totalSupply -= _value;
      // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
      
      // Reset refund state only after successful completion
      refundInProgress[msg.sender] = false;
      pendingRefunds[msg.sender] = 0;
      
      // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
      Transfer(msg.sender, this, _value);
      return true;
    }
    
    function() payable {
      uint256 tokenCount = (msg.value * 1000) / 1 ether ;

      balanceOf[msg.sender] += tokenCount;
      totalSupply += tokenCount;
      Transfer(this, msg.sender, tokenCount);
    }
}