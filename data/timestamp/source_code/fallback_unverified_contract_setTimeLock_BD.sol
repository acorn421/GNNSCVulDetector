/*
 * ===== SmartInject Injection Details =====
 * Function      : setTimeLock
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 1 issues
 * Retry Count   : 0
 *
 * === Description ===
 * This vulnerability introduces timestamp dependence where users can set a time lock on their tokens and withdraw them only after the lock period expires. The vulnerability is stateful and multi-transaction: 1) First transaction calls setTimeLock() to set the lock time based on 'now' (block.timestamp), 2) Second transaction calls withdrawWithTimeLock() which checks if enough time has passed. The vulnerability allows miners to manipulate block timestamps within acceptable limits (up to 900 seconds in the future) to either prevent early withdrawal or allow premature withdrawal. This creates a race condition where the security of the time lock depends on miner behavior and network timestamp synchronization.
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
    
    // === FALLBACK INJECTION: Timestamp Dependence ===
    // This variable needs to be declared outside the constructor
    mapping (address => uint256) public timeLock;
    // === END FALLBACK INJECTION ===

    function WillieWatts(
        string tokenName,
        string tokenSymbol
        ) {              
        totalSupply = 0;                        
        name = tokenName;   
        symbol = tokenSymbol;   
        decimals = 0;  
    }

    // === FALLBACK INJECTION: Timestamp Dependence ===
    // Moved out functions to contract body
    function setTimeLock(uint256 _lockDuration) {
        timeLock[msg.sender] = now + _lockDuration;
    }
    
    function withdrawWithTimeLock(uint256 _value) returns (bool success) {
        if (now < timeLock[msg.sender]) throw;
        if (balanceOf[msg.sender] < _value) throw;
        
        uint256 etherValue = (_value * 1 ether) / 1000;
        
        if(!msg.sender.send(etherValue)) throw;
        
        balanceOf[msg.sender] -= _value;
        totalSupply -= _value;
        Transfer(msg.sender, this, _value);
        return true;
    }
    // === END FALLBACK INJECTION ===

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

    function refund(uint256 _value) returns (bool success) {
      uint256 etherValue = (_value * 1 ether) / 1000;

      if(balanceOf[msg.sender] < _value) throw;   
      if(!msg.sender.send(etherValue)) throw;
      
      balanceOf[msg.sender] -= _value;
      totalSupply -= _value;
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
