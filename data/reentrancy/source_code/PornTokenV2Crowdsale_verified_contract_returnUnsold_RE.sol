/*
 * ===== SmartInject Injection Details =====
 * Function      : returnUnsold
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 1 findings
 * Total Found   : 3 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by:
 * 
 * 1. **Added Daily Withdrawal Limit System**: Created a withdrawal tracking mechanism with daily limits that persist across transactions, requiring multiple calls to withdraw the full amount.
 * 
 * 2. **Violated Checks-Effects-Interactions Pattern**: Moved the external call (tokenReward.transfer) before state updates, creating a reentrancy window where state variables (currentTokenAmount, dailyWithdrawnAmount) are updated after the external call.
 * 
 * 3. **Multi-Transaction Exploitation Path**: 
 *    - **Transaction 1**: Beneficiary calls returnUnsold() to withdraw up to daily limit
 *    - **Transaction 2**: If the malicious token contract reenters during transfer, it can call returnUnsold() again before state updates, bypassing the daily limit check since dailyWithdrawnAmount hasn't been updated yet
 *    - **Subsequent Transactions**: Process can be repeated across multiple days or through sophisticated reentrancy attacks
 * 
 * 4. **Stateful Nature**: The vulnerability relies on persistent state (dailyWithdrawnAmount, lastWithdrawalTime) that accumulates across transactions, making it impossible to exploit in a single atomic transaction.
 * 
 * 5. **Realistic Implementation**: The daily withdrawal limit feature is a common business requirement that makes the vulnerability appear natural and production-ready.
 * 
 * **Exploitation Sequence**:
 * - Day 1: Beneficiary initiates withdrawal → Malicious token contract reenters → State not yet updated → Can withdraw beyond daily limit
 * - Day 2: Daily limit resets → Process can be repeated
 * - The vulnerability requires the state persistence between transactions and the specific timing of external calls vs state updates to be exploitable.
 */
pragma solidity ^0.4.16;

/**
 * PornTokenV2 Crowd Sale
 */

interface token {
    function transfer(address receiver, uint amount);
}

contract PornTokenV2Crowdsale {
    address public beneficiary;
    uint public fundingGoal;
    uint public amountRaised;
    uint private currentBalance;
    uint public deadline;
    uint public price;
    uint public initialTokenAmount;
    uint public currentTokenAmount;
    token public tokenReward;
    mapping(address => uint256) public balanceOf;
    bool fundingGoalReached = false;
    bool crowdsaleClosed = false;

    event GoalReached(address recipient, uint totalAmountRaised);

    /**
     * Constrctor function
     *
     * Setup the owner
     */
    function PornTokenV2Crowdsale(
        address sendTo,
        uint fundingGoalInEthers,
        uint durationInMinutes,
        address addressOfTokenUsedAsReward
    ) {
        beneficiary = sendTo;
        fundingGoal = fundingGoalInEthers * 1 ether;
        deadline = now + durationInMinutes * 1 minutes;
        /* 0.00001337 x 1 ether in wei */
        price = 13370000000000;
        initialTokenAmount = 747943160;
        currentTokenAmount = 747943160;
        tokenReward = token(addressOfTokenUsedAsReward);
    }

    /**
     * Fallback function
     *
     * The function without name is the default function that is called whenever anyone sends funds to a contract
     */
    function () payable {
        require(!crowdsaleClosed);
        uint amount = msg.value;
        if (amount > 0) {
            balanceOf[msg.sender] += amount;
            amountRaised += amount;
            currentBalance += amount;
            uint tokenAmount = (amount / price) * 1 ether;
            currentTokenAmount -= tokenAmount;
            tokenReward.transfer(msg.sender, tokenAmount);
        }
    }

    /**
     * Bank tokens
     *
     * Deposit token sale proceeds to PornToken Account
     */
    function bank() public {
        if (beneficiary == msg.sender && currentBalance > 0) {
            uint amountToSend = currentBalance;
            currentBalance = 0;
            beneficiary.send(amountToSend);
        }
    }
    
    /**
     * Withdraw unusold tokens
     *
     * Deposit unsold tokens to PornToken Account
     */
    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
// Track daily withdrawal limits (reset every 24 hours)
    mapping(address => uint256) public lastWithdrawalTime;
    mapping(address => uint256) public dailyWithdrawnAmount;
    uint256 public constant DAILY_WITHDRAWAL_LIMIT = 100000; // 100k tokens per day
    
    function returnUnsold() public {
        if (beneficiary == msg.sender) {
            // Reset daily limit if 24 hours have passed
            if (block.timestamp > lastWithdrawalTime[msg.sender] + 24 hours) {
                dailyWithdrawnAmount[msg.sender] = 0;
                lastWithdrawalTime[msg.sender] = block.timestamp;
            }
            
            // Calculate how much can be withdrawn today
            uint256 remainingDailyLimit = DAILY_WITHDRAWAL_LIMIT - dailyWithdrawnAmount[msg.sender];
            uint256 withdrawAmount = currentTokenAmount < remainingDailyLimit ? currentTokenAmount : remainingDailyLimit;
            
            require(withdrawAmount > 0, "Daily withdrawal limit exceeded");
            
            // VULNERABILITY: External call before state updates
            tokenReward.transfer(beneficiary, withdrawAmount);
            
            // State updates after external call - vulnerable to reentrancy
            currentTokenAmount -= withdrawAmount;
            dailyWithdrawnAmount[msg.sender] += withdrawAmount;
// ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        }
    }
    
    /**
     * Withdraw unusold tokens
     *
     * Deposit unsold tokens to PornToken Account 100k Safe
     */
    function returnUnsoldSafe() public {
        if (beneficiary == msg.sender) {
            uint tokenAmount = 100000;
            tokenReward.transfer(beneficiary, tokenAmount);
        }
    }

    modifier afterDeadline() { if (now >= deadline) _; }

    /**
     * Check if goal was reached
     *
     * Checks if the goal or time limit has been reached and ends the campaign
     */
    function checkGoalReached() afterDeadline {
        if (amountRaised >= fundingGoal){
            fundingGoalReached = true;
            GoalReached(beneficiary, amountRaised);
        }
        crowdsaleClosed = true;
    }


}