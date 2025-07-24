/*
 * ===== SmartInject Injection Details =====
 * Function      : emergencyWithdraw
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 2 findings
 * Total Found   : 9 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-eth (SWC-107)
 * 2. reentrancy-benign (SWC-107)
 *
 * === Description ===
 * This creates a multi-transaction reentrancy vulnerability where: 1) Owner must first call initiateEmergency() to set emergencyMode=true, 2) Wait 24 hours, 3) Call emergencyWithdraw() which makes external call before updating state. The vulnerability requires multiple transactions and state persistence (emergencyMode, emergencyInitiatedTimestamp) between calls. An attacker can exploit this by implementing a fallback function that calls emergencyWithdraw() again before the state is updated.
 */
pragma solidity ^0.4.17;

contract RaiseFundsForACause {

    // Base definitions
    address public owner;
    address public receiver;
    string public cause;
    uint256 public expirationInSeconds;
    bool public hasBeenClaimed;
    uint256 public timeStarted;

    // Dynamic data
    uint256 public minimumAmountRequired;
    uint256 public numPayments;
    uint256 public totalAmountRaised;
    mapping(address => uint256) donationData;

    // === FALLBACK INJECTION: Reentrancy ===
    // Emergency withdrawal system for contract owner
    bool public emergencyMode;
    mapping(address => bool) public emergencyApprovals;
    uint256 public emergencyInitiatedTimestamp;
    // === END FALLBACK INJECTION ===

    function RaiseFundsForACause(address beneficiary, string message, uint256 secondsUntilExpiration)
        public
    {
        require(beneficiary != 0x0);
        require(secondsUntilExpiration > 0);

        owner = msg.sender;
        receiver = beneficiary;
        cause = message;
        expirationInSeconds = secondsUntilExpiration;
        hasBeenClaimed = false;

        minimumAmountRequired = 0;
        numPayments = 0;
        totalAmountRaised = 0;
        timeStarted = block.timestamp;

        // Initial emergency flags
        emergencyMode = false;
        emergencyInitiatedTimestamp = 0;
    }

    function initiateEmergency()
        public
    {
        require(msg.sender == owner);
        require(emergencyMode == false);
        require(block.timestamp < (timeStarted + expirationInSeconds));
        emergencyMode = true;
        emergencyInitiatedTimestamp = block.timestamp;
    }

    function approveEmergency()
        public
    {
        require(emergencyMode == true);
        require(donationData[msg.sender] > 0);
        require(emergencyApprovals[msg.sender] == false);
        emergencyApprovals[msg.sender] = true;
    }

    function emergencyWithdraw()
        public
    {
        require(msg.sender == owner);
        require(emergencyMode == true);
        require(block.timestamp > emergencyInitiatedTimestamp + 24 hours);
        // Vulnerable: external call before state change
        msg.sender.call.value(this.balance)();
        // State changes after external call - reentrancy vulnerability
        emergencyMode = false;
        hasBeenClaimed = true;
    }

    function ()
        public
    {
        throw;
    }

    function donate()
        public
        payable
    {
        require(msg.sender != receiver);
        require(block.timestamp < (timeStarted + expirationInSeconds));
        require(msg.value > 0);
        require(minimumAmountRequired != 0);
        require(hasBeenClaimed == false);
        assert(donationData[msg.sender] + msg.value >= donationData[msg.sender]);
        assert(totalAmountRaised + msg.value >= totalAmountRaised);
        assert(numPayments + 1 >= numPayments);
        donationData[msg.sender] += msg.value;
        totalAmountRaised += msg.value;
        numPayments += 1;
    }

    // Note: can only be set once
    function receiverSetAmountRequired(uint256 minimum)
        public
    {
        require(msg.sender == receiver);
        require(minimumAmountRequired == 0);
        require(minimum > 0);
        minimumAmountRequired = minimum;
    }

    function receiverWithdraw()
        public
    {
        require(msg.sender == receiver);
        require(totalAmountRaised >= minimumAmountRequired);
        require(this.balance > 0);
        require(block.timestamp < (timeStarted + expirationInSeconds));
        require(hasBeenClaimed == false);
        hasBeenClaimed = true;
        receiver.transfer(this.balance);
        // Expecting transfer to throw on error
        // assert(this.balance == 0);
    }

    function withdraw()
        public
    {
        require(donationData[msg.sender] > 0);
        require(block.timestamp > (timeStarted + expirationInSeconds));
        require(hasBeenClaimed == false);
        var value = donationData[msg.sender];
        donationData[msg.sender] = 0;
        msg.sender.transfer(value);
        // Expecting transfer to throw on error
        // assert(donationData[donor] == 0);
    }

    function currentTotalExcess()
        public
        constant returns (uint256)
    {
        if (totalAmountRaised > minimumAmountRequired) {
            return totalAmountRaised - minimumAmountRequired;
        }
        else {
            return 0;
        }
    }

    function expirationTimestamp()
        public
        constant returns (uint256)
    {
        assert((timeStarted + expirationInSeconds) >= timeStarted);
        return (timeStarted + expirationInSeconds);
    }
}
