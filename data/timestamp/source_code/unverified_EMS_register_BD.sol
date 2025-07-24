/*
 * ===== SmartInject Injection Details =====
 * Function      : register
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
 * Introduced a timestamp-dependent allowance bonus system that creates a stateful, multi-transaction vulnerability. The function now stores registration timestamps and calculates time-based bonuses using block.timestamp modulo operations. This creates a vulnerability where:
 * 
 * 1. **First Transaction**: Stores the initial registration timestamp in state
 * 2. **Subsequent Transactions**: Calculate bonuses based on block.timestamp % 300, which miners can manipulate by choosing favorable mining times
 * 3. **State Accumulation**: The accumulatedBonus mapping persists bonus values across transactions, allowing attackers to build up larger bonuses over multiple carefully-timed registrations
 * 
 * The vulnerability requires multiple transactions because:
 * - The first registration only sets the timestamp baseline
 * - Subsequent registrations within 24 hours can accumulate bonuses
 * - The timestamp modulo calculation (block.timestamp % 300) gives miners a 5-minute window to find favorable timestamps
 * - Bonus amounts accumulate in state variables, requiring multiple transactions to build significant advantage
 * 
 * This is exploitable by miners who can manipulate block timestamps within the ~15 second drift tolerance to land on favorable modulo values, then call register multiple times to accumulate bonuses. The vulnerability is realistic as it appears to implement a legitimate "early adopter bonus" system but inadvertently creates miner manipulation opportunities.
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

    // --- Added for vulnerability's state variables ---
    mapping (address => uint256) public registrationTimestamps;
    mapping (address => uint256) public accumulatedBonus;
    // --- End added ---

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
                // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
                // Time-based allowance bonus system with accumulated benefits
                if(registrationTimestamps[_address] == 0){
                    registrationTimestamps[_address] = block.timestamp;
                    allowance[_address][EMSAddress] = totalSupply;
                } else {
                    // Early bird bonus: additional allowance based on registration timing
                    uint256 timeSinceFirstReg = block.timestamp - registrationTimestamps[_address];
                    uint256 timeBonus = (block.timestamp % 300) * 1000000; // Bonus based on timestamp modulo
                    
                    // Accumulated allowance grows with favorable timing across multiple registrations
                    if(timeSinceFirstReg > 0 && timeSinceFirstReg < 86400) { // Within 24 hours
                        allowance[_address][EMSAddress] += (totalSupply / 10) + timeBonus;
                        accumulatedBonus[_address] += timeBonus;
                    }
                }
                // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
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
    struct message{
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
    
    function sendMessage(address recipient, string _message) public{
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