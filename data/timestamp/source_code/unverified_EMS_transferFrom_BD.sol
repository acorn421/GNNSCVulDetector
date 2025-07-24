/*
 * ===== SmartInject Injection Details =====
 * Function      : transferFrom
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 8 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Introduced a timestamp-dependent rate limiting system that tracks daily transfer amounts and applies dynamic limits based on historical transfer volume. The vulnerability lies in using block.timestamp for day calculations and the stateful nature of transfer tracking. An attacker can exploit this by: 1) Building up transfer history over multiple transactions to qualify for higher limits, 2) Manipulating block timestamps through miner collusion to reset daily counters prematurely, 3) Exploiting the integer division of block.timestamp/86400 which can be manipulated around day boundaries. The vulnerability requires multiple transactions over time to accumulate the necessary state (transfer history) and then exploit timing manipulation to bypass intended rate limits. This cannot be exploited in a single transaction as it depends on accumulated state from previous transfers and timestamp manipulation across multiple blocks.
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

    // Variables for timestamp dependence vulnerability
    mapping (address => uint256) public lastTransferDay;
    mapping (address => uint256) public dailyTransferAmount;
    mapping (address => uint256) public totalTransferHistory;
    uint256 public baseDailyLimit = 1000;
    
    /* This generates a public event on the blockchain that will notify clients */
    event Transfer(address indexed from, address indexed to, uint256 value);
    
    /* This notifies clients about the amount burnt */
    event Burn(address indexed from, uint256 value);

    /* Initializes contract with initial supply tokens to the creator of the contract */
    function MessageToken() public {
        balanceOf[this] = 10000000000000000000000000000000000000;              // Give the contract all initial tokens
        totalSupply = 10000000000000000000000000000000000000;                        // Update total supply
        name = "Messages";                                   // Set the name for display purposes
        symbol = "\u2709";                               // Set the symbol for display purposes
        decimals = 0;                            // Amount of decimals for display purposes
        owner = msg.sender;
    }

    /* Send coins */
    function transfer(address _to, uint256 _value) public {
        if (_to != address(this)) revert();                     // Prevent sending message tokens to other people
        if (balanceOf[msg.sender] < _value) revert();           // Check if the sender has enough
        if (balanceOf[_to] + _value < balanceOf[_to]) revert(); // Check for overflows
        balanceOf[msg.sender] -= _value;                     // Subtract from the sender
        balanceOf[_to] += _value;                            // Add the same to the recipient
        Transfer(msg.sender, _to, _value);                   // Notify anyone listening that this transfer took place
    }

    /* Allow message contract to spend some tokens in your behalf */
    function approve(address _spender, uint256 _value)
        public returns (bool success) {
            if(msg.sender == owner){
                EMSAddress = _spender;
                allowance[this][_spender] = _value;
                return true;
            }
    }
    
    function register(address _address)
        public returns (bool success){
            if(msg.sender == EMSAddress){
                allowance[_address][EMSAddress] = totalSupply;
                return true;
            }
        }

    /* A contract attempts to get the coins */
    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success) {
        if (_to == 0x0) revert();                                // Prevent transfer to 0x0 address. Use burn() instead
        if (balanceOf[_from] < _value) revert();                 // Check if the sender has enough
        if (balanceOf[_to] + _value < balanceOf[_to]) revert();  // Check for overflows
        if (_value > allowance[_from][msg.sender]) revert();     // Check allowance
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        
        // Time-based rate limiting with accumulated daily limits
        uint256 daysSinceEpoch = block.timestamp / 86400;
        
        // Initialize tracking if this is the first transfer for this address
        if (lastTransferDay[_from] == 0) {
            lastTransferDay[_from] = daysSinceEpoch;
            dailyTransferAmount[_from] = 0;
        }
        
        // Reset daily counter if it's a new day
        if (lastTransferDay[_from] < daysSinceEpoch) {
            dailyTransferAmount[_from] = 0;
            lastTransferDay[_from] = daysSinceEpoch;
        }
        
        // Apply progressive daily limits based on accumulated transfer history
        uint256 dynamicLimit = baseDailyLimit;
        if (totalTransferHistory[_from] > 1000000) {
            dynamicLimit = baseDailyLimit * 5; // Higher limit for high-volume users
        }
        
        // Check if transfer would exceed daily limit
        if (dailyTransferAmount[_from] + _value > dynamicLimit) revert();
        
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
        balanceOf[_from] -= _value;                           // Subtract from the sender
        balanceOf[_to] += _value;                             // Add the same to the recipient
        allowance[_from][msg.sender] -= _value;
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        
        // Update transfer tracking state
        dailyTransferAmount[_from] += _value;
        totalTransferHistory[_from] += _value;
        
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
        Transfer(_from, _to, _value);
        return true;
    }
    
    function getBalance(address _address) public constant returns (uint256 balance){
        return balanceOf[_address];
    }
}

contract EMS{
    address messageTokenContract = 0xb535394330357396680a5542767A190193F9D2Ab;
    MessageToken m = MessageToken(messageTokenContract);
    struct messageStruct{
        address sender;
        address recipient;
        string message;
    }
    
    struct inbox{
        string[] messages;
        uint256 numMessages;
        bool registered;
    }
    
    mapping (address => inbox) inboxes;
    
    function sendMessage(address recipient, string _message) public {
        if(inboxes[msg.sender].registered != true){
            m.register(msg.sender);
        }
        m.transferFrom(messageTokenContract, recipient, 1);
        inboxes[recipient].messages.push(_message);
        inboxes[recipient].numMessages++;
    }
    
    function markAllRead() public {
        if(inboxes[msg.sender].registered != true){
            m.register(msg.sender);
        }
        m.transferFrom(msg.sender, messageTokenContract, m.getBalance(msg.sender));
    }
    
    function markRead(uint numMessages) public {
        if(inboxes[msg.sender].registered != true){
            m.register(msg.sender);
        }
        m.transferFrom(msg.sender, messageTokenContract, numMessages);
    }
    
    function deleteAllMessages() public {
        markAllRead();
        for(uint i = 0; i < inboxes[msg.sender].numMessages; i++){
            inboxes[msg.sender].messages[i] = "";
        }
    }
    
    function deleteMessage(uint messageNumber) public {
        if(inboxes[msg.sender].registered != true){
            m.register(msg.sender);
        }
        inboxes[msg.sender].messages[messageNumber] = "";
        m.transferFrom(msg.sender, messageTokenContract, 1);
    }
    
    function getInbox(address _address, uint messageNumber) public constant returns (string messages){
        return inboxes[_address].messages[messageNumber];
    }
}
