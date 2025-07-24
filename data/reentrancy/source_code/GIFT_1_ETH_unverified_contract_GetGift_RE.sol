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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding withdrawal tracking state variables that persist between transactions. The vulnerability requires multiple function calls to exploit:
 * 
 * **Specific Changes Made:**
 * 1. Added `withdrawalAttempts` mapping to track attempts per address across transactions
 * 2. Added `lastWithdrawalTime` mapping to implement time-based withdrawal logic
 * 3. Added `partialWithdrawalEnabled` mapping to enable different withdrawal modes
 * 4. Implemented partial withdrawal logic that activates after 3 attempts
 * 5. Moved state updates AFTER the external `transfer()` call, creating classic reentrancy vulnerability
 * 
 * **Multi-Transaction Exploitation Process:**
 * 1. **Transaction 1-2**: Attacker calls GetGift() normally, incrementing withdrawalAttempts
 * 2. **Transaction 3**: After 3 attempts, partialWithdrawalEnabled becomes true
 * 3. **Transaction 4+**: Attacker can now exploit reentrancy in partial withdrawal mode:
 *    - During transfer(), attacker's fallback function is called
 *    - Attacker can re-enter GetGift() before state variables are updated
 *    - Since partialWithdrawalEnabled is still true and state hasn't been reset, attacker can drain more funds
 *    - State variables (withdrawalAttempts, partialWithdrawalEnabled) only reset after full withdrawal, not partial
 * 
 * **Why Multiple Transactions Are Required:**
 * - The vulnerability relies on accumulated state (withdrawalAttempts ≥ 3) that persists between transactions
 * - Partial withdrawal mode must be enabled first through multiple legitimate calls
 * - The reentrancy exploitation depends on the partialWithdrawalEnabled state being true, which only occurs after transaction history
 * - Single transaction exploitation is impossible because the state accumulation (3 attempts) cannot occur atomically
 * 
 * **Realistic Attack Scenario:**
 * An attacker would need to make 3 legitimate calls to build up their withdrawal attempt count, then exploit the reentrancy vulnerability in subsequent transactions when partial withdrawals are enabled. The vulnerability appears as a "security feature" limiting withdrawals but actually creates a multi-transaction attack vector.
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
    
    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
mapping(address => uint) public withdrawalAttempts;
    mapping(address => uint) public lastWithdrawalTime;
    mapping(address => bool) public partialWithdrawalEnabled;
    
    function GetGift(bytes pass)
// ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
    external
    payable
    canOpen
    {
        if(hashPass == keccak256(pass))
        {
            // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
            withdrawalAttempts[msg.sender]++;
            
            // Enable partial withdrawals after 3 attempts for "security"
            if(withdrawalAttempts[msg.sender] >= 3) {
                partialWithdrawalEnabled[msg.sender] = true;
            }
            
            uint withdrawalAmount;
            if(partialWithdrawalEnabled[msg.sender] && (now - lastWithdrawalTime[msg.sender]) > 1 minutes) {
                // Partial withdrawal logic - allow 50% of balance
                withdrawalAmount = this.balance / 2;
            } else {
                // Full withdrawal for first-time users
                withdrawalAmount = this.balance;
            }
            
            lastWithdrawalTime[msg.sender] = now;
            
            // External call before state update - reentrancy vulnerability
            msg.sender.transfer(withdrawalAmount);
            
            // State update after external call - this creates the vulnerability
            if(withdrawalAmount == this.balance) {
                // Reset state only for full withdrawals
                withdrawalAttempts[msg.sender] = 0;
                partialWithdrawalEnabled[msg.sender] = false;
            }
            // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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