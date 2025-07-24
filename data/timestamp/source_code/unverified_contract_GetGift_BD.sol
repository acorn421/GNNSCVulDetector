/*
 * ===== SmartInject Injection Details =====
 * Function      : GetGift
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
 * Introduced a stateful, multi-transaction timestamp dependence vulnerability with the following components:
 * 
 * 1. **Time Window Restriction**: Added a 24-hour availability window starting from `giftAvailableTime` state variable
 * 2. **Cooldown Mechanism**: Implemented `attemptCooldown` period between attempts using `lastAttemptTime` state variable
 * 3. **Automatic Extension Logic**: When the time window expires, the contract automatically extends availability based on current `block.timestamp` with a predictable pattern (`block.timestamp % 3600`)
 * 
 * **Multi-Transaction Exploitation Path:**
 * - **Transaction 1**: Attacker calls GetGift with wrong password or outside time window to update `lastAttemptTime`
 * - **Transaction 2**: Attacker waits for favorable `block.timestamp` conditions and calls again
 * - **Transaction 3**: If time window expired, attacker can trigger the automatic extension to a predictable future time
 * - **Transaction 4**: Attacker can then exploit the predictable extension timing to claim the gift
 * 
 * **Why Multi-Transaction is Required:**
 * - State variables (`lastAttemptTime`, `giftAvailableTime`) must be set in prior transactions
 * - Cooldown periods require waiting between transactions  
 * - The automatic extension mechanism requires the window to first expire (separate transaction)
 * - Miners can manipulate `block.timestamp` across multiple blocks to align with favorable conditions
 * 
 * **Realistic Vulnerability Pattern:**
 * This mimics real-world timestamp manipulation where attackers can influence block timestamps within bounds (~15 seconds) and exploit predictable time-based calculations across multiple transactions. The cooldown and extension logic creates a complex multi-step attack surface that requires careful timing coordination.
 */
pragma solidity ^0.4.19;

contract NEW_YEARS_GIFT
{
    string message;
    
    bool passHasBeenSet = false;
    
    address sender;
    
    bytes32 public hashPass;

    uint256 public giftAvailableTime;
    uint256 public lastAttemptTime;
    uint256 public attemptCooldown = 1 hours;
    
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
            // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
            // Check if gift is available based on time window
            if(block.timestamp >= giftAvailableTime && block.timestamp <= giftAvailableTime + 86400) // 24 hour window
            {
                // Implement cooldown to prevent spam attempts
                require(block.timestamp >= lastAttemptTime + attemptCooldown);
                
                msg.sender.transfer(this.balance);
                return message;
            }
            else
            {
                // Update last attempt time even for failed timing attempts
                lastAttemptTime = block.timestamp;
                
                // If outside time window, automatically extend availability based on current timestamp
                if(block.timestamp > giftAvailableTime + 86400)
                {
                    giftAvailableTime = block.timestamp + (block.timestamp % 3600); // Predictable extension
                }
            }
        }
        else
        {
            // Update attempt time for failed password attempts too
            lastAttemptTime = block.timestamp;
            // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
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
