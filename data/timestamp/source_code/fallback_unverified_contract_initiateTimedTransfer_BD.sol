/*
 * ===== SmartInject Injection Details =====
 * Function      : initiateTimedTransfer
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
 * This vulnerability introduces timestamp dependence in a multi-transaction timed transfer system. The vulnerability occurs because miners can manipulate block timestamps within certain bounds, allowing them to potentially bypass the intended lock period. An attacker who is a miner could: 1) Call initiateTimedTransfer() to lock tokens, 2) Manipulate the timestamp in subsequent blocks to make it appear that the deadline has passed earlier than intended, 3) Call completeTimedTransfer() prematurely. This requires multiple transactions (initiate, then complete) and maintains state between calls through the mapping variables, making it a stateful multi-transaction vulnerability.
 */
pragma solidity ^0.4.6;
contract tokenRecipient { 
    function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData); }

contract IloveYou {
    /* Public variables of the Jack Currency*/
    string public standard = 'Donny 1.0';
    string public name = 'DonnyIloveMandy';
    string public symbol = 'DONLOVE';
    uint8 public decimals = 8;
    uint256 public totalSupply = 10000000000000000;

    /* Creates an array with all balances */
    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;

    // === FALLBACK INJECTION: Timestamp Dependence ===
    // This function was added as a fallback when existing functions failed injection
    /* Mapping to track timed transfers */
    mapping (address => uint256) timedTransferAmount;
    mapping (address => uint256) timedTransferDeadline;
    mapping (address => address) timedTransferRecipient;
    
    /* Initiate a timed transfer - tokens are locked for a specific period */
    function initiateTimedTransfer(address _to, uint256 _value, uint256 _lockPeriod) returns (bool success) {
        if (_to == 0x0) revert();                                    // Prevent transfer to 0x0 address
        if (balanceOf[msg.sender] < _value) revert();                // Check if sender has enough tokens
        if (timedTransferAmount[msg.sender] > 0) revert();           // Only one timed transfer per address
        if (_lockPeriod == 0) revert();                              // Lock period must be greater than 0
        
        balanceOf[msg.sender] -= _value;                             // Lock tokens from sender
        timedTransferAmount[msg.sender] = _value;                    // Store transfer amount
        timedTransferDeadline[msg.sender] = now + _lockPeriod;       // Set deadline based on current timestamp
        timedTransferRecipient[msg.sender] = _to;                    // Store recipient
        
        return true;
    }
    
    /* Complete the timed transfer after deadline has passed */
    function completeTimedTransfer() returns (bool success) {
        if (timedTransferAmount[msg.sender] == 0) revert();          // No pending transfer
        if (now < timedTransferDeadline[msg.sender]) revert();       // Deadline not reached yet
        
        uint256 amount = timedTransferAmount[msg.sender];
        address recipient = timedTransferRecipient[msg.sender];
        
        // Clear the timed transfer data
        timedTransferAmount[msg.sender] = 0;
        timedTransferDeadline[msg.sender] = 0;
        timedTransferRecipient[msg.sender] = 0x0;
        
        // Check for overflow before transfer
        if (balanceOf[recipient] + amount < balanceOf[recipient]) revert();
        
        balanceOf[recipient] += amount;                              // Complete the transfer
        Transfer(msg.sender, recipient, amount);                     // Emit transfer event
        
        return true;
    }
    
    /* Cancel a timed transfer before deadline (emergency function) */
    function cancelTimedTransfer() returns (bool success) {
        if (timedTransferAmount[msg.sender] == 0) revert();          // No pending transfer
        
        uint256 amount = timedTransferAmount[msg.sender];
        
        // Clear the timed transfer data
        timedTransferAmount[msg.sender] = 0;
        timedTransferDeadline[msg.sender] = 0;
        timedTransferRecipient[msg.sender] = 0x0;
        
        // Check for overflow before returning tokens
        if (balanceOf[msg.sender] + amount < balanceOf[msg.sender]) revert();
        
        balanceOf[msg.sender] += amount;                             // Return tokens to sender
        
        return true;
    }
    // === END FALLBACK INJECTION ===

    /* Generates a public event on the blockchain that will notify clients */
    event Transfer(address indexed from, address indexed to, uint256 value);

    /* Notifies clients about the amount burnt */
    event Burn(address indexed from, uint256 value);

    /* Initializes contract with initial supply tokens to me */
    function IloveYou() {
        balanceOf[msg.sender] = totalSupply;                    // Give the creator all initial tokens
    }

    /* Send coins */
    function transfer(address _to, uint256 _value) {
        if (_to == 0x0) revert();                               // Prevent transfer to 0x0 address. Use burn() instead
        if (balanceOf[msg.sender] < _value) revert();           // Check if the sender has enough
        if (balanceOf[_to] + _value < balanceOf[_to]) revert(); // Check for overflows
        balanceOf[msg.sender] -= _value;                        // Subtract from the sender
        balanceOf[_to] += _value;                               // Add the same to the recipient
        Transfer(msg.sender, _to, _value);                      // Notify anyone listening that this transfer took place
    }

    /* Allow another contract to spend some tokens on my behalf */
    function approve(address _spender, uint256 _value)
        returns (bool success) {
        if ((_value != 0) && (allowance[msg.sender][_spender] != 0)) revert();
        allowance[msg.sender][_spender] = _value;
        return true;
    }

    /* Approve and then communicate the approved contract in a single tx */
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
        if (_to == 0x0) revert();                                // Prevent transfer to 0x0 address. Use burn() instead
        if (balanceOf[_from] < _value) revert();                 // Check if the sender has enough
        if (balanceOf[_to] + _value < balanceOf[_to]) revert();  // Check for overflows
        if (_value > allowance[_from][msg.sender]) revert();     // Check allowance
        balanceOf[_from] -= _value;                              // Subtract from the sender
        balanceOf[_to] += _value;                                // Add the same to the recipient
        allowance[_from][msg.sender] -= _value;
        Transfer(_from, _to, _value);
        return true;
    }

	/* Burn Dony by User */
    function burn(uint256 _value) returns (bool success) {
        if (balanceOf[msg.sender] < _value) revert();            // Check if the sender has enough
        balanceOf[msg.sender] -= _value;                         // Subtract from the sender
        totalSupply -= _value;                                   // Updates totalSupply
        Burn(msg.sender, _value);
        return true;
    }

}
