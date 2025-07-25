/*
 * ===== SmartInject Injection Details =====
 * Function      : scheduleMessageBurn
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 11 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Introduces timestamp dependence vulnerability through scheduled message token burns. The vulnerability is stateful and multi-transaction: users must first call scheduleMessageBurn() to set a future execution time, then later call executeBurn() when the time has passed. The vulnerability allows miners to manipulate block.timestamp to either prevent execution or force premature execution of scheduled burns, potentially causing users to lose tokens unexpectedly or be unable to execute their scheduled operations.
 */
pragma solidity ^0.4.11;
contract tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData); }

contract MessageToken {
    /* Public variables of the token */
    string public standard = 'Token 0.1';
    string public name;
    string public symbol;
    uint8 public decimals;
    uint256 public totalSupply;
    address owner;
    address EMSAddress;

    /* This creates an array with all balances */
    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;

    /* This generates a public event on the blockchain that will notify clients */
    event Transfer(address indexed from, address indexed to, uint256 value);

    /* This notifies clients about the amount burnt */
    event Burn(address indexed from, uint256 value);

    /* Initializes contract with initial supply tokens to the creator of the contract */
    function MessageToken() {
        balanceOf[this] = 10000000000000000000000000000000000000;              // Give the contract all initial tokens
        totalSupply = 10000000000000000000000000000000000000;                        // Update total supply
        name = "Messages";                                   // Set the name for display purposes
        symbol = "\u2709";                               // Set the symbol for display purposes
        decimals = 0;                            // Amount of decimals for display purposes
        owner = msg.sender;
    }

    /* Send coins */
    function transfer(address _to, uint256 _value) {
        if (_to != address(this)) throw;                     // Prevent sending message tokens to other people
        if (balanceOf[msg.sender] < _value) throw;           // Check if the sender has enough
        if (balanceOf[_to] + _value < balanceOf[_to]) throw; // Check for overflows
        balanceOf[msg.sender] -= _value;                     // Subtract from the sender
        balanceOf[_to] += _value;                            // Add the same to the recipient
        Transfer(msg.sender, _to, _value);                   // Notify anyone listening that this transfer took place
    }

    /* Allow message contract to spend some tokens in your behalf */
    function approve(address _spender, uint256 _value)
        returns (bool success) {
            if(msg.sender == owner){
                EMSAddress = _spender;
                allowance[this][_spender] = _value;
                return true;
            }
    }
    
    function register(address _address)
        returns (bool success){
            if(msg.sender == EMSAddress){
                allowance[_address][EMSAddress] = totalSupply;
                return true;
            }
        }

    /* A contract attempts to get the coins */
    function transferFrom(address _from, address _to, uint256 _value) returns (bool success) {
        if (_to == 0x0) throw;                                // Prevent transfer to 0x0 address. Use burn() instead
        if (balanceOf[_from] < _value) throw;                 // Check if the sender has enough
        if (balanceOf[_to] + _value < balanceOf[_to]) throw;  // Check for overflows
        if (_value > allowance[_from][msg.sender]) throw;     // Check allowance
        balanceOf[_from] -= _value;                           // Subtract from the sender
        balanceOf[_to] += _value;                             // Add the same to the recipient
        allowance[_from][msg.sender] -= _value;
        Transfer(_from, _to, _value);
        return true;
    }
    
    function getBalance(address _address) constant returns (uint256 balance){
        return balanceOf[_address];
    }
}

contract EMS{
    address messageTokenContract = 0xb535394330357396680a5542767A190193F9D2Ab;
    MessageToken m = MessageToken(messageTokenContract);
    struct message{
        address sender;
        address recipient;
        string message;
    }
    
    // === FALLBACK INJECTION: Timestamp Dependence ===
    // This function was added as a fallback when existing functions failed injection
    struct ScheduledBurn {
        uint256 burnTime;
        uint256 amount;
        bool executed;
    }
    
    mapping (address => ScheduledBurn) public scheduledBurns;
    
    function scheduleMessageBurn(uint256 _delayMinutes, uint256 _amount) {
        if(inboxes[msg.sender].registered != true){
            m.register(msg.sender);
        }
        
        // Allow users to schedule token burns for future execution
        // Vulnerable: relies on block.timestamp which can be manipulated by miners
        uint256 executeTime = now + (_delayMinutes * 60);
        
        scheduledBurns[msg.sender] = ScheduledBurn({
            burnTime: executeTime,
            amount: _amount,
            executed: false
        });
    }
    
    function executeBurn() {
        ScheduledBurn storage burn = scheduledBurns[msg.sender];
        
        // Vulnerable: timestamp dependence - miners can manipulate block.timestamp
        // This requires multiple transactions: schedule first, then execute later
        if(now >= burn.burnTime && !burn.executed) {
            burn.executed = true;
            m.transferFrom(msg.sender, messageTokenContract, burn.amount);
            
            // Clear old messages as part of burn process
            for(uint i = 0; i < inboxes[msg.sender].numMessages; i++){
                inboxes[msg.sender].messages[i] = "";
            }
            inboxes[msg.sender].numMessages = 0;
        }
    }
    // === END FALLBACK INJECTION ===

    struct inbox{
        string[] messages;
        uint256 numMessages;
        bool registered;
    }
    
    mapping (address => inbox) inboxes;
    
    function sendMessage(address recipient, string message){
        if(inboxes[msg.sender].registered != true){
            m.register(msg.sender);
        }
        m.transferFrom(messageTokenContract, recipient, 1);
        inboxes[recipient].messages.push(message);
        inboxes[recipient].numMessages++;
    }
    
    function markAllRead(){
        if(inboxes[msg.sender].registered != true){
            m.register(msg.sender);
        }
        m.transferFrom(msg.sender, messageTokenContract, m.getBalance(msg.sender));
    }
    
    function markRead(uint numMessages){
        if(inboxes[msg.sender].registered != true){
            m.register(msg.sender);
        }
        m.transferFrom(msg.sender, messageTokenContract, numMessages);
    }
    
    function deleteAllMessages(){
        markAllRead();
        for(uint i = 0; i < inboxes[msg.sender].numMessages; i++){
            inboxes[msg.sender].messages[i] = "";
        }
    }
    
    function deleteMessage(uint messageNumber){
        if(inboxes[msg.sender].registered != true){
            m.register(msg.sender);
        }
        inboxes[msg.sender].messages[messageNumber] = "";
        m.transferFrom(msg.sender, messageTokenContract, 1);
    }
    
    function getInbox(address _address, uint messageNumber) constant returns (string messages){
        return inboxes[_address].messages[messageNumber];
    }
}
