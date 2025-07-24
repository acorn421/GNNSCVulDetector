/*
 * ===== SmartInject Injection Details =====
 * Function      : SetPass
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 2 findings
 * Total Found   : 3 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-benign (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the previous sender before state updates. This creates a classic violation of the checks-effects-interactions pattern where external calls occur before state changes.
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 
 * **Transaction 1** (Setup Phase):
 * - Attacker calls SetPass() with >1 ether, becomes the sender
 * - State is set: sender = attacker, hashPass = attacker_hash
 * 
 * **Transaction 2** (Exploitation Phase):
 * - Victim calls SetPass() with >1 ether and different hash
 * - Function executes: sender.call() is made to attacker (the current sender)
 * - During the external call, attacker's contract receives control
 * - Attacker reenters SetPass() with their original hash and >1 ether
 * - Since state hasn't been updated yet, attacker can reset their preferred hash
 * - Original victim's transaction continues and updates state, but with potentially compromised values
 * 
 * **Why Multi-Transaction is Required:**
 * 1. **State Dependency**: The vulnerability relies on having a previous sender already set in state from a prior transaction
 * 2. **Accumulated State**: The exploit requires the contract to have accumulated state (previous sender) that enables the external call
 * 3. **Sequence Dependency**: The attack requires a specific sequence - first establishing attacker as sender, then exploiting the notification mechanism
 * 4. **Persistent State Manipulation**: The reentrancy can manipulate state that persists between transactions, affecting subsequent operations
 * 
 * **Real-World Relevance:**
 * This pattern mimics real vulnerabilities where contracts notify stakeholders about state changes, creating reentrancy opportunities that depend on accumulated state from previous transactions.
 */
pragma solidity ^0.4.19;

contract GIFT_1_ETH
{
    bytes32 public hashPass;
    
    bool closed = false;
    
    address sender;
 
    uint unlockTime;
 
    function GetHash(bytes pass) public constant returns (bytes32) {return keccak256(pass);}
    
    function SetPass(bytes32 hash)
    public
    payable
    {
        if( (!closed&&(msg.value > 1 ether)) || hashPass==0x00 )
        {
            // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
            // Notify previous sender before updating state
            if(sender != address(0)) {
                // External call to notify previous sender about password change
                sender.call(bytes4(keccak256("passwordChanged(bytes32,address)")), hash, msg.sender);
            }
            
            // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
            hashPass = hash;
            sender = msg.sender;
            unlockTime = now;
        }
    }
    
    function SetGiftTime(uint date)
    public
    {
        if(msg.sender==sender)
        {
            unlockTime = date;
        }
    }
    
    function GetGift(bytes pass)
    external
    payable
    canOpen
    {
        if(hashPass == keccak256(pass))
        {
            msg.sender.transfer(this.balance);
        }
    }
    
    function Revoce()
    public
    payable
    canOpen
    {
        if(msg.sender==sender)
        {
            sender.transfer(this.balance);
        }
    }
    
    function PassHasBeenSet(bytes32 hash)
    public
    {
        if(hash==hashPass&&msg.sender==sender)
        {
           closed=true;
        }
    }
    
    modifier canOpen
    {
        require(now>unlockTime);
        _;
    }
    
    function() public payable{}
    
}