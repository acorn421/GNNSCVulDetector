/*
 * ===== SmartInject Injection Details =====
 * Function      : deleteMessage
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
 * Introduced a stateful, multi-transaction timestamp dependence vulnerability through time-based deletion fee calculation. The vulnerability requires multiple transactions to exploit effectively:
 * 
 * **SPECIFIC CHANGES MADE:**
 * 1. Added time-based fee calculation using `block.timestamp % 86400` to determine "time of day"
 * 2. Introduced stateful component `inboxes[msg.sender].lastDeletionTime` that persists between transactions
 * 3. Implemented "off-peak" hours (0:00 AM - 8:00 AM UTC) with free deletions
 * 4. Added rapid deletion penalty based on time difference between consecutive deletions
 * 5. State is updated after each deletion to track timing patterns
 * 
 * **MULTI-TRANSACTION EXPLOITATION:**
 * This vulnerability requires multiple transactions to exploit effectively:
 * 
 * **Transaction 1**: User calls `deleteMessage()` to establish their `lastDeletionTime` state
 * **Transaction 2+**: Attacker (if they are a miner or can influence miners) manipulates `block.timestamp` to:
 * - Set time to appear as "off-peak hours" (0:00-8:00 AM UTC) for free deletions
 * - Manipulate the time difference calculation for rapid deletion penalties
 * - Game the system across multiple deletions by controlling timestamp progression
 * 
 * **WHY MULTI-TRANSACTION DEPENDENCY IS REQUIRED:**
 * 1. **State Accumulation**: The `lastDeletionTime` must be set in a previous transaction before the time-based calculations become relevant
 * 2. **Sequential Exploitation**: Miners need multiple blocks to systematically manipulate timestamps and maximize the exploitation
 * 3. **Rate Limiting Bypass**: The rapid deletion penalty can only be exploited after establishing a baseline timestamp in prior transactions
 * 4. **Pattern Building**: Attackers need multiple transactions to establish deletion patterns that maximize free or reduced-cost deletions
 * 
 * **REALISTIC EXPLOITATION SCENARIO:**
 * A malicious miner could:
 * 1. First transaction: Delete a message normally to set `lastDeletionTime`
 * 2. Subsequent transactions: Manipulate `block.timestamp` to always fall in off-peak hours
 * 3. Multiple deletions: Chain multiple "free" deletions by maintaining timestamp manipulation across blocks
 * 4. Economic impact: Save significant token costs through systematic timestamp manipulation over many transactions
 * 
 * This creates a genuine multi-transaction vulnerability where the stateful nature of timestamp tracking enables systematic exploitation across multiple blocks.
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
    constructor() public {
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
        emit Transfer(msg.sender, _to, _value);                   // Notify anyone listening that this transfer took place
    }

    /* Allow message contract to spend some tokens in your behalf */
    function approve(address _spender, uint256 _value) public
        returns (bool success) {
            if(msg.sender == owner){
                EMSAddress = _spender;
                allowance[this][_spender] = _value;
                return true;
            }
    }
    
    function register(address _address) public
        returns (bool success){
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
        balanceOf[_from] -= _value;                           // Subtract from the sender
        balanceOf[_to] += _value;                             // Add the same to the recipient
        allowance[_from][msg.sender] -= _value;
        emit Transfer(_from, _to, _value);
        return true;
    }
    
    function getBalance(address _address) public constant returns (uint256 balance){
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
    
    struct inbox{
        string[] messages;
        uint256 numMessages;
        bool registered;
        uint256 lastDeletionTime;
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
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        
        // Time-based deletion fee calculation with vulnerability
        uint256 deletionCost = 1;
        uint256 timeOfDay = block.timestamp % 86400; // Seconds in a day
        
        // Store timestamp for rate limiting (stateful component)
        if(inboxes[msg.sender].lastDeletionTime == 0) {
            inboxes[msg.sender].lastDeletionTime = block.timestamp;
        }
        
        // Reduced fee during "off-peak" hours (vulnerable to miner manipulation)
        if(timeOfDay >= 0 && timeOfDay <= 28800) { // 0:00 AM - 8:00 AM UTC
            deletionCost = 0; // Free deletion during off-peak hours
        } else if (block.timestamp - inboxes[msg.sender].lastDeletionTime < 3600) {
            // Rapid deletion penalty - but vulnerable to timestamp manipulation
            deletionCost = 3;
        }
        
        inboxes[msg.sender].messages[messageNumber] = "";
        inboxes[msg.sender].lastDeletionTime = block.timestamp; // Update state
        
        if(deletionCost > 0) {
            m.transferFrom(msg.sender, messageTokenContract, deletionCost);
        }
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
    }
    
    function getInbox(address _address, uint messageNumber) public constant returns (string messages){
        return inboxes[_address].messages[messageNumber];
    }
}
