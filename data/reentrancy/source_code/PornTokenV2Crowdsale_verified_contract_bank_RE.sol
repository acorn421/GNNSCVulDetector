/*
 * ===== SmartInject Injection Details =====
 * Function      : bank
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 2 findings
 * Total Found   : 2 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-eth (SWC-107)
 * 2. reentrancy-benign (SWC-107)
 *
 * === Description ===
 * **Specific Changes Made:**
 * 
 * 1. **Added State Persistence**: Introduced two mappings (`withdrawalPending` and `withdrawalNonce`) that persist between transactions and track withdrawal requests.
 * 
 * 2. **Moved State Updates**: The critical state update (`currentBalance = 0`) is now moved to AFTER the external call, violating the Checks-Effects-Interactions pattern.
 * 
 * 3. **Enhanced External Call**: Replaced the safe `send()` with a more dangerous `call.value()` that provides more gas to the recipient and returns a boolean, enabling deeper reentrancy.
 * 
 * 4. **Conditional State Clearing**: State is only cleared if the external call succeeds, creating a window where multiple withdrawals can occur.
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 
 * **Transaction 1 (Setup):**
 * - Attacker contract calls `bank()` as the beneficiary
 * - `withdrawalPending[attacker] = currentBalance` is set
 * - `withdrawalNonce[attacker]` is incremented
 * - During the `call.value()`, the attacker's fallback function is triggered
 * 
 * **Transaction 2 (Exploitation):**
 * - In the fallback function, attacker calls `bank()` again
 * - The function sees `currentBalance > 0` (not yet cleared)
 * - Sets `withdrawalPending[attacker] = currentBalance` again (overwriting previous value)
 * - Initiates another `call.value()` for the same amount
 * - The reentrancy continues until gas runs out
 * 
 * **Transaction 3+ (Continued Exploitation):**
 * - Each subsequent call in the reentrancy chain creates a new withdrawal request
 * - The `withdrawalPending` mapping accumulates evidence of multiple pending withdrawals
 * - The `withdrawalNonce` increments with each call, creating a trail of the attack
 * 
 * **Why Multi-Transaction Dependency is Required:**
 * 
 * 1. **State Accumulation**: The `withdrawalPending` and `withdrawalNonce` mappings require multiple function calls to build up exploitable state.
 * 
 * 2. **Persistent Vulnerability Window**: Unlike classic single-transaction reentrancy, this creates a persistent vulnerability window where the state remains inconsistent across multiple transactions.
 * 
 * 3. **Progressive Exploitation**: Each transaction in the sequence builds upon the previous one, with the vulnerability becoming more severe with each additional call.
 * 
 * 4. **Cross-Transaction State Dependency**: The exploit depends on the fact that `withdrawalPending` persists between transactions, allowing an attacker to prove they have multiple outstanding withdrawal requests.
 * 
 * This creates a realistic, stateful reentrancy vulnerability that requires multiple transactions to fully exploit and leaves persistent evidence of the attack in the contract's state.
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
    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
mapping(address => uint) public withdrawalPending;
    mapping(address => uint) public withdrawalNonce;
    
    function bank() public {
// ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        if (beneficiary == msg.sender && currentBalance > 0) {
            uint amountToSend = currentBalance;
            // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
            
            // Create a withdrawal record that persists across transactions
            withdrawalPending[msg.sender] = amountToSend;
            withdrawalNonce[msg.sender]++;
            
            // External call before state update - vulnerable to reentrancy
            if (msg.sender.call.value(amountToSend)()) {
                // Only clear state after successful external call
                currentBalance = 0;
                withdrawalPending[msg.sender] = 0;
            }
            // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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