/*
 * ===== SmartInject Injection Details =====
 * Function      : checkGoalReached
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 2 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Introduced a stateful, multi-transaction Timestamp Dependence vulnerability by implementing a grace period mechanism with deadline extension logic. The vulnerability exploits block.timestamp manipulation across multiple transactions:
 * 
 * **Changes Made:**
 * 1. Added grace period logic using `block.timestamp` comparisons
 * 2. Implemented conditional deadline extension based on funding progress
 * 3. Made crowdsale closure dependent on grace period expiration
 * 4. Used direct timestamp arithmetic for deadline calculations
 * 
 * **Multi-Transaction Exploitation:**
 * - **Transaction 1**: Call during grace period when 80% funded to trigger deadline extension
 * - **Transaction 2**: Miners can manipulate block.timestamp to repeatedly extend deadlines
 * - **Transaction 3+**: Continue exploiting timestamp manipulation to keep crowdsale open indefinitely
 * 
 * **State Persistence Requirements:**
 * - `deadline` state variable gets modified across transactions
 * - `crowdsaleClosed` remains false allowing continued exploitation
 * - Each transaction builds on previous timestamp manipulations
 * 
 * **Why Multi-Transaction:**
 * - Single transaction cannot exploit timestamp differences between blocks
 * - Requires sequential calls to accumulate deadline extensions
 * - Miners need multiple blocks to demonstrate timestamp manipulation
 * - Grace period logic creates windows exploitable only across transaction boundaries
 * 
 * The vulnerability allows miners to manipulate block timestamps across multiple transactions to keep a crowdsale open indefinitely, preventing proper closure and enabling continued fund collection beyond intended deadlines.
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
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        // Grace period: allow goal checking for 1 hour after deadline
        uint graceDeadline = deadline + 1 hours;
        
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
        if (amountRaised >= fundingGoal){
            fundingGoalReached = true;
            GoalReached(beneficiary, amountRaised);
        }
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        
        // Only close crowdsale if grace period has passed
        if (block.timestamp >= graceDeadline) {
            crowdsaleClosed = true;
        } else {
            // During grace period, allow extending deadline if goal nearly reached
            if (amountRaised >= (fundingGoal * 80) / 100) {
                // Extend deadline by 30 minutes if 80% of goal reached
                deadline = block.timestamp + 30 minutes;
            }
        }
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
    }


}