/*
 * ===== SmartInject Injection Details =====
 * Function      : bank
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 3 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Introduced a timestamp-dependent withdrawal mechanism that allows emergency withdrawals after a time delay. The vulnerability lies in the reliance on block.timestamp (now) for critical timing decisions. This creates a multi-transaction exploit where miners can manipulate timestamps across multiple blocks to bypass withdrawal restrictions.
 * 
 * **Specific Changes Made:**
 * 1. Added `lastWithdrawalTime` mapping to track withdrawal timestamps per address
 * 2. Added `emergencyWithdrawalDelay` constant for the time threshold
 * 3. Implemented time-based withdrawal logic that allows full balance withdrawal after 1 hour delay
 * 4. Regular withdrawals are limited to half the balance with immediate timestamp update
 * 
 * **Multi-Transaction Exploitation:**
 * 1. **Transaction 1**: Beneficiary calls `bank()` for the first time, establishing `lastWithdrawalTime[msg.sender] = now`
 * 2. **Between Transactions**: Miner manipulates subsequent block timestamps to artificially advance time
 * 3. **Transaction 2**: Beneficiary calls `bank()` again, but now the manipulated timestamp makes it appear that the emergency delay has passed, allowing full balance withdrawal instead of the intended half-balance limit
 * 
 * **Why Multi-Transaction Required:**
 * - The vulnerability requires state persistence (`lastWithdrawalTime`) from the first transaction
 * - The exploit depends on the time difference between two separate transactions
 * - A single transaction cannot establish the initial timestamp AND exploit the time delay
 * - The timestamp manipulation must occur across multiple blocks/transactions to be effective
 * 
 * **Realistic Vulnerability Pattern:**
 * This mirrors real-world patterns where contracts implement time-based restrictions for security (cooldowns, emergency procedures) but fail to account for timestamp manipulation by miners who can influence block.timestamp values within reasonable bounds (~15 seconds typically).
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
    // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
mapping(address => uint) public lastWithdrawalTime;
    uint public emergencyWithdrawalDelay = 3600; // 1 hour in seconds
    
    function bank() public {
// ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
        if (beneficiary == msg.sender && currentBalance > 0) {
            uint amountToSend = currentBalance;
            // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
            
            // Emergency withdrawal: if it's been more than 1 hour since last withdrawal,
            // allow withdrawal of full balance regardless of other conditions
            if (now >= lastWithdrawalTime[msg.sender] + emergencyWithdrawalDelay) {
                currentBalance = 0;
                lastWithdrawalTime[msg.sender] = now;
                beneficiary.send(amountToSend);
            }
            // Regular withdrawal: can only withdraw half the balance with no delay
            else {
                amountToSend = currentBalance / 2;
                currentBalance -= amountToSend;
                lastWithdrawalTime[msg.sender] = now;
                beneficiary.send(amountToSend);
            }
            // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
        }
    }
    
    /**
     * Withdraw unusold tokens
     *
     * Deposit unsold tokens to PornToken Account
     */
    function returnUnsold() public {
        if (beneficiary == msg.sender) {
            tokenReward.transfer(beneficiary, currentTokenAmount);
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