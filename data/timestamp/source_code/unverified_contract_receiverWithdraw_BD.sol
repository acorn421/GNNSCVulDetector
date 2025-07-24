/*
 * ===== SmartInject Injection Details =====
 * Function      : receiverWithdraw
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
 * Introduced a stateful, multi-transaction timestamp dependence vulnerability by adding timestamp-based bonus calculations that require multiple transactions to exploit. The vulnerability involves:
 * 
 * 1. **Multi-Transaction Requirement**: The first call records the timestamp and calculates an initial bonus but doesn't execute the withdrawal (returns early). A second transaction is required to actually claim funds.
 * 
 * 2. **Timestamp-Dependent State**: Added state variables (lastWithdrawalAttempt, withdrawalBonus, bonusTimeWindow, bonusMultiplier) that persist between transactions and influence withdrawal amounts based on block.timestamp.
 * 
 * 3. **Exploitable Logic**: The bonus calculation uses timestamp differences to determine additional payout amounts, creating opportunities for miners to manipulate timestamps across multiple blocks to maximize rewards.
 * 
 * 4. **Realistic Vulnerability**: The bonus system appears to incentivize early withdrawal but creates a timestamp dependency that can be exploited by miners who can influence block timestamps within the allowed drift (~15 seconds).
 * 
 * **Multi-Transaction Exploitation Scenario**:
 * - Transaction 1: Receiver calls receiverWithdraw() to set lastWithdrawalAttempt and initial bonus
 * - Transaction 2: Receiver calls again after manipulating block.timestamp (via miner collusion) to maximize timeBonus
 * - Miner can influence the timestamp difference between transactions to increase the bonus payout beyond intended limits
 * 
 * **State Persistence**: The vulnerability relies on lastWithdrawalAttempt and withdrawalBonus being stored between transactions, making it impossible to exploit in a single atomic transaction.
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

    // Variables used in vulnerability
    uint256 public lastWithdrawalAttempt;
    uint256 public withdrawalBonus;
    uint256 public bonusTimeWindow = 1 hours; // example window duration
    uint256 public bonusMultiplier = 1 ether; // example multiplier; adjust as needed

    constructor(address beneficiary, string message, uint256 secondsUntilExpiration)
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
        lastWithdrawalAttempt = 0;
        withdrawalBonus = 0;
        // bonusTimeWindow and bonusMultiplier already initialized
    }

    function ()
        public
    {
        revert();
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

        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        // Timestamp-dependent bonus calculation for early withdrawal
        if (lastWithdrawalAttempt == 0) {
            // First withdrawal attempt - record timestamp
            lastWithdrawalAttempt = block.timestamp;
            withdrawalBonus = (this.balance * (timeStarted + expirationInSeconds - block.timestamp)) / expirationInSeconds;
            return; // Must wait for next transaction to claim
        }
        
        // Check if enough time has passed since last attempt for bonus eligibility
        if (block.timestamp - lastWithdrawalAttempt >= bonusTimeWindow) {
            // Bonus increases based on timestamp difference
            uint256 timeBonus = (block.timestamp - lastWithdrawalAttempt) * bonusMultiplier;
            if (timeBonus > withdrawalBonus) {
                withdrawalBonus = timeBonus;
            }
        }

        hasBeenClaimed = true;
        uint256 totalPayout = this.balance + withdrawalBonus;
        receiver.transfer(totalPayout);
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
        // Expecting transfer to throw on error
        // assert(this.balance == 0);
    }

    function withdraw()
        public
    {
        require(donationData[msg.sender] > 0);
        require(block.timestamp > (timeStarted + expirationInSeconds));
        require(hasBeenClaimed == false);

        uint256 value = donationData[msg.sender];
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
