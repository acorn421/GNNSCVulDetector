/*
 * ===== SmartInject Injection Details =====
 * Function      : Revoce
 * Vulnerability : Reentrancy
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 0 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by:
 * 
 * 1. **Added state persistence window**: The function now sets `sender = address(0)` AFTER the external call, creating a window where the original sender authorization remains valid during reentrancy.
 * 
 * 2. **Multi-transaction exploitation path**: 
 *    - **Transaction 1**: Legitimate call to Revoce() begins transfer process
 *    - **Transaction 2+**: During the transfer execution, if sender is a contract, it can re-enter Revoce() while `sender` still equals `msg.sender` (not yet reset to address(0))
 *    - **State accumulation**: Each reentrant call can drain the contract balance before the original transaction completes and resets the sender
 * 
 * 3. **Stateful dependency**: The vulnerability requires:
 *    - Initial transaction to establish the withdrawal context
 *    - Accumulated state where `sender` remains unchanged during the transfer
 *    - Multiple reentrant calls that exploit the persistent authorization state
 * 
 * 4. **Realistic vulnerability pattern**: This mirrors real-world reentrancy bugs where authorization state is not properly updated before external calls, allowing attackers to exploit the window between external call initiation and state finalization.
 * 
 * **Exploitation Scenario**:
 * - Attacker (as authorized sender) calls Revoce()
 * - During sender.transfer(), attacker's contract receive() function is triggered
 * - Attacker can call Revoce() again since sender hasn't been reset yet
 * - Multiple draining cycles possible before original transaction completes
 * - Each cycle requires separate transaction context, making it stateful and multi-transaction dependent
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
            // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
            uint256 withdrawalAmount = this.balance;
            // Allow partial withdrawals through accumulation
            if(withdrawalAmount > 0) {
                sender.transfer(withdrawalAmount);
                // State update after external call - creates reentrancy window
                message="";
                // Reset sender only after successful withdrawal
                sender = address(0);
            }
            // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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