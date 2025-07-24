/*
 * ===== SmartInject Injection Details =====
 * Function      : checkGoalReached
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
 * 1. reentrancy-benign (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the beneficiary contract after the GoalReached event but before setting crowdsaleClosed = true. This creates a reentrancy window where the beneficiary contract can call back into the crowdsale contract while crowdsaleClosed is still false, potentially allowing manipulation of contract state across multiple transactions. The vulnerability requires: (1) Initial transaction calling checkGoalReached() when funding goal is met, (2) Beneficiary contract implementing goalReached() callback that re-enters the crowdsale, (3) Subsequent transactions exploiting the manipulated state before crowdsaleClosed is finally set. The attack is multi-transaction because it depends on the persistent state of crowdsaleClosed remaining false during the reentrancy window, and the exploitation requires coordinated calls across multiple transactions to manipulate the crowdsale state while it's in this vulnerable intermediate state.
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
        if (amountRaised >= fundingGoal){
            fundingGoalReached = true;
            GoalReached(beneficiary, amountRaised);
            // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
            // Notify beneficiary of goal reached - vulnerable to reentrancy
            beneficiary.call(bytes4(keccak256("goalReached(uint256)")), amountRaised);
            // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        }
        crowdsaleClosed = true;
    }


}