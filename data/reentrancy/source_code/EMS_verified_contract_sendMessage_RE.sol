/*
 * ===== SmartInject Injection Details =====
 * Function      : sendMessage
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 4 findings
 * Total Found   : 8 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-no-eth (SWC-107)
 * 3. reentrancy-no-eth (SWC-107)
 * ... and 1 more
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by:
 * 
 * 1. **Added External Call to Recipient Contract**: Introduced a call to `tokenRecipient(recipient).receiveApproval()` before the token transfer, creating a reentrancy point where the recipient can call back into the contract.
 * 
 * 2. **Moved Critical State Updates After External Call**: The message storage (`inboxes[recipient].messages.push(message)`) and counter increment (`inboxes[recipient].numMessages++`) now occur after the external call, violating the checks-effects-interactions pattern.
 * 
 * 3. **Added Recipient Registration State**: Added registration logic for the recipient that occurs before the external call, creating a window where the recipient is marked as registered but message state is inconsistent.
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 
 * **Transaction 1 (Setup)**: Attacker deploys a malicious contract that implements `receiveApproval()` and calls `sendMessage()` with their malicious contract as the recipient.
 * 
 * **Transaction 2 (Initial Message)**: Legitimate user sends a message to the malicious contract:
 * - Malicious contract gets registered (`inboxes[malicious].registered = true`)
 * - External call triggers malicious contract's `receiveApproval()`
 * - During reentrancy, malicious contract calls `sendMessage()` again to itself
 * - First call completes, adding message and incrementing counter
 * - Original call resumes and adds another message, incrementing counter again
 * - Result: 2 messages stored but inconsistent state
 * 
 * **Transaction 3 (Exploitation)**: Attacker exploits the accumulated inconsistent state:
 * - Uses the inflated message count to manipulate other contract functions
 * - Can potentially drain tokens by exploiting the mismatch between actual messages and `numMessages` counter
 * - Can overflow storage or manipulate message indexing in other functions
 * 
 * **Why Multi-Transaction Dependency is Required:**
 * 
 * 1. **State Accumulation**: The vulnerability requires building up inconsistent state over multiple calls where `numMessages` becomes higher than actual messages stored.
 * 
 * 2. **Registration Persistence**: The recipient registration state persists between transactions, enabling the malicious contract to be called in subsequent transactions.
 * 
 * 3. **Compound Effect**: Each reentrancy call compounds the state inconsistency, requiring multiple interactions to reach an exploitable state.
 * 
 * 4. **Cross-Function Exploitation**: The inconsistent state created in `sendMessage()` can be exploited in other functions like `getInbox()`, `deleteMessage()`, or `markRead()` that rely on the message count.
 * 
 * The vulnerability is realistic because it introduces a callback mechanism commonly seen in token contracts while maintaining the original function's purpose, but creates a dangerous reentrancy window that allows state manipulation across multiple transactions.
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
        emit Transfer(msg.sender, _to, _value);                   // Notify anyone listening that this transfer took place
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
    }
    
    mapping (address => inbox) inboxes;
    
    function sendMessage(address recipient, string _message) public {
        if(inboxes[msg.sender].registered != true){
            m.register(msg.sender);
        }
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // State update before external call for recipient registration
        if(inboxes[recipient].registered != true){
            inboxes[recipient].registered = true;
        }
        
        // External call to recipient (potential reentrancy point)
        // Use extcodesize in inline assembly for code size check
        uint256 size;
        assembly {
            size := extcodesize(recipient)
        }
        if(size > 0){
            tokenRecipient(recipient).receiveApproval(msg.sender, 1, messageTokenContract, bytes(_message));
        }
        
        // Token transfer after external call
        m.transferFrom(messageTokenContract, recipient, 1);
        
        // Critical state updates after external call (vulnerable to reentrancy)
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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