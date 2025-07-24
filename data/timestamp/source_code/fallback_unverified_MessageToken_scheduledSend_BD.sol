/*
 * ===== SmartInject Injection Details =====
 * Function      : scheduledSend
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
 * This vulnerability introduces timestamp dependence through a multi-transaction scheduled messaging system. Users can schedule messages to be sent at future timestamps and receive token rewards when executed. The vulnerability requires: 1) First transaction to schedule a message with a future timestamp, 2) Wait for the timestamp condition, 3) Second transaction to execute and claim rewards. Miners can manipulate block timestamps to execute scheduled messages earlier than intended, allowing them to claim rewards prematurely or prevent legitimate executions by setting timestamps that don't meet the condition.
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
    struct scheduledMessage {
        address sender;
        address recipient;
        string message;
        uint256 sendTime;
        bool executed;
        uint256 tokenReward;
    }
    
    mapping(uint256 => scheduledMessage) public scheduledMessages;
    uint256 public nextScheduledId = 1;
    
    function scheduleMessage(address recipient, string message, uint256 delayMinutes) public returns (uint256) {
        if(inboxes[msg.sender].registered != true){
            m.register(msg.sender);
        }
        
        uint256 sendTime = now + (delayMinutes * 60);
        uint256 messageId = nextScheduledId++;
        
        scheduledMessages[messageId] = scheduledMessage({
            sender: msg.sender,
            recipient: recipient,
            message: message,
            sendTime: sendTime,
            executed: false,
            tokenReward: delayMinutes // Reward based on delay
        });
        
        m.transferFrom(msg.sender, messageTokenContract, 1);
        return messageId;
    }
    
    function executeScheduledMessage(uint256 messageId) public {
        scheduledMessage storage scheduled = scheduledMessages[messageId];
        
        if(scheduled.executed) throw;
        if(now < scheduled.sendTime) throw;
        if(scheduled.sender == address(0)) throw;
        
        // Send the message
        inboxes[scheduled.recipient].messages.push(scheduled.message);
        inboxes[scheduled.recipient].numMessages++;
        
        // Mark as executed
        scheduled.executed = true;
        
        // Give reward tokens to executor (vulnerable to timestamp manipulation)
        m.transferFrom(messageTokenContract, msg.sender, scheduled.tokenReward);
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
