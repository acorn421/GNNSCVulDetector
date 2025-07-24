/*
 * ===== SmartInject Injection Details =====
 * Function      : returnUnsold
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 4 issues
 * Retry Count   : 0
 *
 * === Description ===
 * This vulnerability introduces timestamp dependence through multiple mechanisms creating a stateful, multi-transaction exploit scenario:
 * 
 * **Specific Changes Made:**
 * 1. **Time-based Access Control**: Added a 30-day cooling period after the crowdsale deadline using `block.timestamp >= deadline + 30 days`
 * 2. **Block Number as Time Proxy**: Implemented withdrawal amount calculation using `block.number` as a time proxy with the formula `((block.number - (deadline / 15)) % 1000) * 1000`
 * 3. **Stateful Partial Withdrawals**: Modified the function to support partial withdrawals that update `currentTokenAmount` state between transactions
 * 
 * **Multi-Transaction Exploitation Path:**
 * 1. **Transaction 1**: Beneficiary calls `returnUnsold()` after the 30-day period when timing conditions result in a partial withdrawal
 * 2. **State Change**: `currentTokenAmount` is reduced but not zeroed, maintaining exploitable state
 * 3. **Transaction 2**: Attacker (if they can influence block timing) or beneficiary waits for favorable block numbers and calls again
 * 4. **Repeated Exploitation**: Multiple calls can be made to drain tokens incrementally based on manipulated timing
 * 
 * **Why Multiple Transactions Are Required:**
 * - The vulnerability cannot be exploited in a single transaction because it depends on the accumulated state changes to `currentTokenAmount`
 * - Each withdrawal updates the contract state, affecting subsequent withdrawal calculations
 * - The timing-dependent logic creates windows where different withdrawal amounts are possible
 * - Miners can manipulate `block.timestamp` and influence `block.number` progression to create favorable conditions across multiple blocks
 * - The modulo operation with block numbers creates cyclical opportunities that must be exploited across multiple transactions
 * 
 * **Realistic Attack Scenario:**
 * A malicious miner could manipulate block timestamps to either:
 * - Accelerate the 30-day cooling period to enable early withdrawals
 * - Influence the block number calculations to maximize withdrawal amounts across multiple transactions
 * - Create favorable timing windows for repeated partial withdrawals
 * 
 * This creates a realistic timestamp dependence vulnerability that requires state accumulation and multiple transaction sequences to fully exploit.
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
    function returnUnsold() public {
        if (beneficiary == msg.sender) {
            // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
            // Time-based withdrawal restriction: must wait 30 days after crowdsale deadline
            require(block.timestamp >= deadline + 30 days, "Withdrawal cooling period not met");
            
            // Additional timestamp-based logic using block.number as time proxy
            uint timeBasedLimit = ((block.number - (deadline / 15)) % 1000) * 1000; // ~15 sec blocks
            
            if (timeBasedLimit > 0 && currentTokenAmount > timeBasedLimit) {
                // Partial withdrawal based on block timing
                tokenReward.transfer(beneficiary, timeBasedLimit);
                currentTokenAmount -= timeBasedLimit;
            } else {
                // Full withdrawal if timing conditions are met
                tokenReward.transfer(beneficiary, currentTokenAmount);
                currentTokenAmount = 0;
            }
            // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
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