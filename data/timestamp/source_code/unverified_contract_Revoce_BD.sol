/*
 * ===== SmartInject Injection Details =====
 * Function      : Revoce
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 1 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Introduced a stateful, multi-transaction timestamp dependence vulnerability by implementing a 24-hour cooling-off period for revocation. The vulnerability requires two separate transactions: first to request revocation (storing block.timestamp), then to execute it after the time delay. This creates a window where miners can manipulate block timestamps to either accelerate or delay the revocation process. The vulnerability is stateful because it persists revocation state variables between transactions, and multi-transaction because it requires at least two function calls separated by time to complete the revocation process. This realistic security measure (preventing immediate fund withdrawal) introduces a timing-based attack vector that could be exploited by miners controlling block timestamps.
 */
pragma solidity ^0.4.19;

contract NEW_YEARS_GIFT
{
    string message;
    
    bool passHasBeenSet = false;
    
    address sender;
    
    bytes32 public hashPass;

    // Declare the missing state variables required for Revoce
    uint256 revocationRequestTime = 0;
    bool revocationRequested = false;
    
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
            // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
            if(revocationRequestTime == 0)
            {
                revocationRequestTime = block.timestamp;
                revocationRequested = true;
            }
            else if(revocationRequested && block.timestamp >= revocationRequestTime + 24 hours)
            {
                sender.transfer(this.balance);
                message="";
                revocationRequestTime = 0;
                revocationRequested = false;
            }
            // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
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
