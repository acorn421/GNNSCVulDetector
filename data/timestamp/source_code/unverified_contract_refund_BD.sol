/*
 * ===== SmartInject Injection Details =====
 * Function      : refund
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 1 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Introduced a stateful, multi-transaction Timestamp Dependence vulnerability by adding:
 * 
 * 1. **State Variables**: Added `lastRefundTime`, `refundWindowStart`, and `refundCooldown` mappings to track user refund timing across transactions.
 * 
 * 2. **Cooldown Period**: Implemented a 5-minute cooldown between refunds using `block.timestamp`, which is manipulable by miners within ~15 seconds.
 * 
 * 3. **Time-Based Refund Rates**: Added increasingly favorable refund rates based on time elapsed since first refund (10% bonus after 1 hour, 20% after 2 hours).
 * 
 * **Multi-Transaction Exploitation:**
 * - **Transaction 1**: User calls refund() to establish `refundWindowStart` timestamp
 * - **Transaction 2+**: User waits or manipulates timing to bypass cooldown and gain better rates
 * - **Miner Collaboration**: Miners can manipulate `block.timestamp` to help users bypass cooldowns or reach bonus thresholds prematurely
 * 
 * **Why Multi-Transaction Required:**
 * - The vulnerability requires state accumulation across calls (`lastRefundTime`, `refundWindowStart`)
 * - Cooldown enforcement depends on previous transaction timestamps
 * - Bonus rates are calculated from historical state, not single-transaction data
 * - Exploitation requires strategic timing across multiple blocks/transactions
 * 
 * **Realistic Exploitation Scenario:**
 * An attacker could collaborate with miners to manipulate block timestamps, allowing them to:
 * 1. Bypass cooldown periods through timestamp manipulation
 * 2. Artificially advance time to reach bonus refund rates
 * 3. Create favorable timing windows across multiple refund transactions
 * 4. Exploit the predictable nature of block.timestamp in sequential transactions
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

    // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
// Add state variables for timestamp tracking (should be added to contract)
    mapping (address => uint256) public lastRefundTime;
    mapping (address => uint256) public refundWindowStart;
    uint256 public refundCooldown = 300; // 5 minutes
    
    function refund(uint256 _value) returns (bool success) {
// ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
      uint256 etherValue = (_value * 1 ether) / 1000;

      if(balanceOf[msg.sender] < _value) throw;   
      // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
      
      // Initialize refund window if first time
      if (lastRefundTime[msg.sender] == 0) {
          refundWindowStart[msg.sender] = block.timestamp;
      }
      
      // Check if within cooldown period - vulnerable to timestamp manipulation
      if (block.timestamp < lastRefundTime[msg.sender] + refundCooldown) {
          throw; // Still in cooldown
      }
      
      // Time-based refund rate calculation - vulnerable to block timestamp manipulation
      uint256 timeElapsed = block.timestamp - refundWindowStart[msg.sender];
      uint256 refundRate = 1000;
      
      // Increase refund rate over time - creates timestamp dependency
      if (timeElapsed > 3600) { // After 1 hour
          refundRate = 1100; // 10% bonus
      }
      if (timeElapsed > 7200) { // After 2 hours  
          refundRate = 1200; // 20% bonus
      }
      
      etherValue = (_value * 1 ether) / refundRate;
      
      // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
      if(!msg.sender.send(etherValue)) throw;
      
      balanceOf[msg.sender] -= _value;
      totalSupply -= _value;
      // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
      
      // Update timestamp state - creates multi-transaction dependency
      lastRefundTime[msg.sender] = block.timestamp;
      
      // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
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