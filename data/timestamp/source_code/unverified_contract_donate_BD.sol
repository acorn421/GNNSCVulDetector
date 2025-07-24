/*
 * ===== SmartInject Injection Details =====
 * Function      : donate
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
 * Introduced a timestamp-dependent bonus system that creates a multi-transaction vulnerability where miners can manipulate block.timestamp to repeatedly qualify for early bird bonuses across multiple donation transactions. The vulnerability requires state accumulation (effectiveAmount tracking) and sequential exploitation over multiple transactions.
 * 
 * **Specific Changes Made:**
 * 1. Added time-based bonus calculation using block.timestamp - timeStarted
 * 2. Implemented early bird bonus tiers (150% in first quarter, 125% in second quarter)
 * 3. Applied bonus multiplier to create effectiveAmount that gets stored in state
 * 4. State variables now track amplified donation amounts rather than actual ETH values
 * 
 * **Multi-Transaction Exploitation:**
 * 1. **First Transaction**: Attacker makes initial donation when legitimately in early bird period
 * 2. **Subsequent Transactions**: Miner manipulates block.timestamp (within ~15 second tolerance) to:
 *    - Make it appear donations are still in early bird period
 *    - Qualify for 150% or 125% bonus repeatedly
 *    - Accumulate inflated donation tracking that persists in state
 * 
 * **Why Multiple Transactions Are Required:**
 * - Single transaction exploitation is limited by natural timestamp constraints
 * - The vulnerability becomes profitable through accumulated bonus effects over multiple donations
 * - State persistence allows manipulation effects to compound across transactions
 * - Each transaction builds on previous state modifications, creating cumulative advantage
 * - The bonus system creates incentive for repeated exploitation rather than one-time manipulation
 * 
 * **Realistic Attack Vector:**
 * A malicious miner could coordinate to:
 * 1. Accept transactions during legitimate early bird periods
 * 2. Manipulate subsequent block timestamps to maintain bonus eligibility
 * 3. Execute multiple donations across several blocks to maximize bonus accumulation
 * 4. Build up inflated totalAmountRaised and donationData values that persist between transactions
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

        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        // Calculate time-based bonus using block.timestamp
        uint256 bonusMultiplier = 100; // Base 100% (no bonus)
        uint256 timeElapsed = block.timestamp - timeStarted;
        uint256 quarterPeriod = expirationInSeconds / 4;
        
        // Early bird bonus: 150% in first quarter, 125% in second quarter
        if (timeElapsed < quarterPeriod) {
            bonusMultiplier = 150;
        } else if (timeElapsed < quarterPeriod * 2) {
            bonusMultiplier = 125;
        }
        
        // Apply bonus to donation amount for tracking purposes
        uint256 effectiveAmount = (msg.value * bonusMultiplier) / 100;
        
        donationData[msg.sender] += effectiveAmount;
        totalAmountRaised += effectiveAmount;
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
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