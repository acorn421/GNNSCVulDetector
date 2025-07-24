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
 * Total Found   : 2 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-eth (SWC-107)
 * 2. reentrancy-benign (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to msg.sender before state updates. The vulnerability requires multiple transactions to exploit:
 * 
 * **Specific Changes Made:**
 * 1. Added external call via `msg.sender.call.value()` before state updates
 * 2. The call transfers 10% of msg.value back to the sender as a "callback notification"
 * 3. State updates (hashPass and sender) now occur AFTER the external call
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 1. **Transaction 1**: Attacker deploys malicious contract and calls SetPass with >1 ether
 * 2. **During Callback**: Malicious contract's fallback function reenters SetPass with different parameters
 * 3. **State Manipulation**: During reentrancy, hashPass is still the old value, allowing bypass of conditions
 * 4. **Transaction 2+**: Attacker exploits the inconsistent state where multiple "senders" can be set or hashPass can be manipulated
 * 
 * **Why Multi-Transaction Required:**
 * - The vulnerability exploits the time window between external call and state updates
 * - First transaction establishes initial state and triggers reentrancy
 * - Reentrant calls manipulate state while original transaction's effects are pending
 * - Subsequent transactions can exploit the resulting inconsistent state between passHasBeenSet, hashPass, and sender variables
 * - The accumulated state changes persist across transactions, enabling complex exploitation patterns
 * 
 * **State Dependencies:**
 * - passHasBeenSet flag (managed by other functions) creates cross-transaction dependencies
 * - hashPass and sender assignments can be manipulated during reentrancy window
 * - The contract's authentication system becomes vulnerable to state race conditions across multiple calls
 */
pragma solidity ^0.4.19;

contract NEW_YEARS_GIFT
{
    string message;
    
    bool passHasBeenSet = false;
    
    address sender;
    
    bytes32 public hashPass;
	
	function() public payable{}
    
    function GetHash(bytes pass) public constant returns (bytes32) {return sha3(pass);}
    
    function SetPass(bytes32 hash)
    public
    payable
    {
        if( (!passHasBeenSet&&(msg.value > 1 ether)) || hashPass==0x0 )
        {
            // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
            // Add external call before state updates - creates reentrancy opportunity
            if(msg.value > 0) {
                // Notify sender of password setup attempt via callback
                bool success = msg.sender.call.value(msg.value / 10)("");
                require(success, "Callback failed");
            }
            
            // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
            hashPass = hash;
            sender = msg.sender;
        }
    }
    
    function SetMessage(string _message)
    public
    {
        if(msg.sender==sender)
        {
            message =_message;
        }
    }
    
    function GetGift(bytes pass)
    external
    payable
    returns (string)
    {
        if(hashPass == sha3(pass))
        {
            msg.sender.transfer(this.balance);
            return message;
        }
    }
    
    function Revoce()
    public
    payable
    {
        if(msg.sender==sender)
        {
            sender.transfer(this.balance);
            message="";
        }
    }
    
    function PassHasBeenSet(bytes32 hash)
    public
    {
        if(msg.sender==sender&&hash==hashPass)
        {
           passHasBeenSet=true;
        }
    }
}