/*
 * ===== SmartInject Injection Details =====
 * Function      : transferFrom
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 4 findings
 * Total Found   : 9 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-no-eth (SWC-107)
 * 3. reentrancy-no-eth (SWC-107)
 * ... and 1 more
 *
 * === Description ===
 * This vulnerability introduces a stateful, multi-transaction reentrancy attack by adding an external call to the recipient contract after balance updates but before allowance reduction. The vulnerability requires multiple transactions to exploit:
 * 
 * **Transaction 1 (Setup)**: Attacker deploys a malicious contract and obtains approval/allowance from a victim account to spend tokens.
 * 
 * **Transaction 2 (Exploitation)**: The attacker calls transferFrom, which updates balances and then calls the malicious contract's receiveApproval function. The malicious contract can then reenter transferFrom in the same transaction, exploiting the fact that the allowance hasn't been reduced yet, but the balances have been updated.
 * 
 * **Multi-Transaction Nature**: The vulnerability requires multiple transactions because:
 * 1. The attacker needs to set up allowances in prior transactions
 * 2. The exploit leverages the state inconsistency window where balances are updated but allowances aren't reduced yet
 * 3. The external call to receiveApproval creates a reentrancy opportunity that persists across transaction boundaries
 * 4. The attacker must prepare the malicious contract and allowance setup before the actual exploitation
 * 
 * **Exploitation Scenario**: 
 * 1. Transaction 1: Victim approves attacker's contract to spend tokens
 * 2. Transaction 2: Attacker calls transferFrom → balances updated → external call → reentrant transferFrom call uses same allowance again
 * 3. The stateful nature means the allowance reduction happens after the external call, creating a window for reentrancy
 * 
 * This creates a realistic CEI (Checks-Effects-Interactions) violation where effects (balance updates) happen before interactions (external call), followed by more effects (allowance reduction), enabling multi-transaction reentrancy exploitation.
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
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Transfer notification callback for contracts
        if (_to != address(0) && isContract(_to)) {
            tokenRecipient(_to).receiveApproval(_from, _value, this, "");
        }
        
        allowance[_from][msg.sender] -= _value;               // Allowance reduction after external call
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        Transfer(_from, _to, _value);
        return true;
    }
    
    function getBalance(address _address) constant returns (uint256 balance){
        return balanceOf[_address];
    }
    
    // Helper function to check if an address is a contract (replacement for code.length in 0.4.x)
    function isContract(address _addr) internal constant returns (bool) {
        uint size;
        assembly { size := extcodesize(_addr) }
        return size > 0;
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