/*
 * ===== SmartInject Injection Details =====
 * Function      : pauseCampaign
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 6 issues
 * Retry Count   : 0
 *
 * === Description ===
 * This introduces a timestamp dependence vulnerability where the contract owner can manipulate campaign timing through strategic pausing and unpausing. The vulnerability is stateful and requires multiple transactions: 1) First transaction to pause the campaign, 2) Second transaction to unpause within a specific timeframe to extend the campaign duration. The vulnerability exploits the unreliable nature of block.timestamp and allows the owner to extend campaigns unfairly by controlling pause timing.
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

    // === FALLBACK INJECTION: Timestamp Dependence ===
    // Emergency pause functionality - only owner can pause
    bool public isPaused;
    uint256 public pauseStartTime;
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
        isPaused = false;
        pauseStartTime = 0;
    }

    function pauseCampaign()
        public
    {
        require(msg.sender == owner);
        require(hasBeenClaimed == false);
        require(block.timestamp < (timeStarted + expirationInSeconds));

        isPaused = true;
        pauseStartTime = block.timestamp;
    }

    function unpauseCampaign()
        public
    {
        require(msg.sender == owner);
        require(isPaused == true);

        // Vulnerable: Owner can manipulate timing by controlling when they unpause
        // If paused for less than 1 hour, extend campaign by pause duration
        if (block.timestamp - pauseStartTime < 3600) {
            expirationInSeconds += (block.timestamp - pauseStartTime);
        }

        isPaused = false;
        pauseStartTime = 0;
    }

    function checkPauseStatus()
        public
        constant returns (bool, uint256)
    {
        return (isPaused, pauseStartTime);
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
