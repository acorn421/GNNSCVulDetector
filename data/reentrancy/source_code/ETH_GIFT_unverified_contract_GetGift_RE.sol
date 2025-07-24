/*
 * ===== SmartInject Injection Details =====
 * Function      : GetGift
 * Vulnerability : Reentrancy
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
 * Introduced a stateful, multi-transaction reentrancy vulnerability through a withdrawal limiting system. The vulnerability requires multiple transactions to exploit:
 * 
 * **Specific Changes Made:**
 * 1. **Added State Variables**: 
 *    - `withdrawalAttempts` mapping to track withdrawal count per user
 *    - `lastWithdrawalTime` mapping to enforce time delays
 *    - `withdrawalDelay` for time-based restrictions
 *    - `maxWithdrawalPerCall` to limit per-transaction withdrawals
 *    - `emergencyMode` boolean that changes behavior after multiple attempts
 * 
 * 2. **Added Time-Based Logic**: Users must wait 5 minutes between withdrawals, creating natural multi-transaction requirements
 * 
 * 3. **Implemented Withdrawal Limits**: Regular mode only allows 1 ether per call, requiring multiple transactions to drain larger balances
 * 
 * 4. **Vulnerable State Update Pattern**: The critical flaw - `lastWithdrawalTime[msg.sender] = block.timestamp` occurs AFTER the external call, creating a reentrancy window
 * 
 * 5. **Emergency Mode Trigger**: After 3 withdrawal attempts, emergency mode activates allowing full balance withdrawal
 * 
 * **Multi-Transaction Exploitation Path:**
 * - **Transaction 1**: Attacker calls GetGift, gets limited withdrawal, but lastWithdrawalTime isn't updated due to reentrancy
 * - **Transaction 2**: Since lastWithdrawalTime wasn't properly updated, delay check passes, another withdrawal occurs
 * - **Transaction 3**: After 3 attempts, emergencyMode becomes true, enabling full balance drainage
 * - **Transaction 4**: With emergencyMode active, attacker can now withdraw entire remaining balance
 * 
 * **Why Multiple Transactions Are Required:**
 * 1. **Time Delay Enforcement**: The 5-minute delay between calls naturally requires multiple transactions
 * 2. **Withdrawal Limits**: Regular mode limits prevent single-transaction drainage
 * 3. **State Accumulation**: Emergency mode only activates after multiple withdrawal attempts
 * 4. **Reentrancy Window**: Each individual call has limited impact, but accumulated state corruption enables escalating exploitation
 * 
 * The vulnerability is realistic as it mimics common patterns in DeFi protocols with withdrawal limits and emergency mechanisms.
 */
pragma solidity ^0.4.19;

contract ETH_GIFT
{
    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
mapping(address => uint) public withdrawalAttempts;
    mapping(address => uint) public lastWithdrawalTime;
    uint public withdrawalDelay = 300; // 5 minutes delay
    uint public maxWithdrawalPerCall = 1 ether;
    bool public emergencyMode = false;
    
    function GetGift(bytes pass)
// ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
    external
    payable
    {
        if(hashPass == keccak256(pass))
        {
            // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
            // Check if enough time has passed since last withdrawal
            if(withdrawalAttempts[msg.sender] > 0 && 
               block.timestamp < lastWithdrawalTime[msg.sender] + withdrawalDelay)
            {
                revert("Withdrawal delay not met");
            }
            
            uint withdrawAmount;
            
            // Emergency mode allows full withdrawal
            if(emergencyMode)
            {
                withdrawAmount = this.balance;
            }
            else
            {
                // Regular mode: limited withdrawal per call
                withdrawAmount = this.balance > maxWithdrawalPerCall ? 
                                maxWithdrawalPerCall : this.balance;
            }
            
            // Increment withdrawal attempts before external call
            withdrawalAttempts[msg.sender]++;
            
            // VULNERABILITY: External call before state update
            msg.sender.transfer(withdrawAmount);
            
            // State update happens AFTER external call - creates reentrancy window
            lastWithdrawalTime[msg.sender] = block.timestamp;
            
            // Emergency mode can be triggered after multiple withdrawals
            if(withdrawalAttempts[msg.sender] >= 3)
            {
                emergencyMode = true;
            }
            // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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
    
}