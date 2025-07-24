/*
 * ===== SmartInject Injection Details =====
 * Function      : approve
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 1 findings
 * Total Found   : 8 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-benign (SWC-107)
 *
 * === Description ===
 * **Specific Changes Made:**
 * 
 * 1. **Reordered State Updates**: Moved `allowance[this][_spender] = _value;` before the external call
 * 2. **Added External Call**: Introduced `tokenRecipient(_spender).receiveApproval(...)` call that enables reentrancy
 * 3. **Critical State After External Call**: Moved `EMSAddress = _spender;` to occur AFTER the external call, violating the Checks-Effects-Interactions pattern
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 
 * **Transaction 1 (Setup):**
 * - Owner calls `approve(maliciousContract, 1000)` to set initial allowance
 * - During `receiveApproval()` callback, malicious contract can reenter but allowance is already set
 * - `EMSAddress` gets set to maliciousContract after the callback completes
 * 
 * **Transaction 2 (Exploitation):**
 * - Attacker calls `approve(attackerContract, 2000)` 
 * - The `allowance[this][attackerContract] = 2000` is set first
 * - During `receiveApproval()` callback, attackerContract reenters `approve()`
 * - In the reentered call, it can set `allowance[this][attackerContract] = 5000`
 * - When the callback returns, the original call sets `EMSAddress = attackerContract`
 * - This creates inconsistent state where allowance is 5000 but EMSAddress points to a different value
 * 
 * **Transaction 3 (Profit):**
 * - Attacker can now use the inflated allowance in `transferFrom()` or other functions
 * - The `EMSAddress` state can be manipulated to control which contract has special privileges
 * 
 * **Why Multi-Transaction is Required:**
 * 
 * 1. **State Accumulation**: The vulnerability depends on the EMSAddress state being set in previous transactions to establish the attack context
 * 2. **Reentrancy Setup**: The malicious contract needs to be established as a valid spender first before it can effectively reenter
 * 3. **Consistent State Window**: The attack exploits the window between setting allowance and EMSAddress, requiring multiple calls to maximize the inconsistent state
 * 4. **Privilege Escalation**: The attacker needs multiple transactions to escalate from basic allowance to controlling the EMSAddress, which grants additional system privileges
 * 
 * The vulnerability creates a persistent state inconsistency that compounds across multiple transactions, making it impossible to exploit in a single atomic transaction.
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
                // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
                // Set the allowance first (vulnerable pattern)
                allowance[this][_spender] = _value;
                
                // External call to notify spender - potential reentrancy point
                tokenRecipient(_spender).receiveApproval(msg.sender, _value, this, "");
                
                // State change after external call - vulnerable to manipulation
                // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
                EMSAddress = _spender;
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