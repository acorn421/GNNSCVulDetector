/*
 * ===== SmartInject Injection Details =====
 * Function      : withdraw
 * Vulnerability : Reentrancy
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
 * **Specific Changes Made:**
 * 
 * 1. **Reversed Order of Operations**: Moved the state update `donationData[msg.sender] = 0` to AFTER the external call `msg.sender.transfer(value)`, violating the Checks-Effects-Interactions (CEI) pattern.
 * 
 * 2. **Created Reentrancy Window**: The external call now occurs before the state is cleared, creating a window where the contract's state still shows the user has funds available for withdrawal.
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 
 * **Transaction 1 (Setup)**: Attacker donates funds to the contract using the `donate()` function, which sets `donationData[attacker] = donationAmount`.
 * 
 * **Transaction 2 (Initial Withdrawal)**: After the fundraising period expires, attacker calls `withdraw()`:
 * - Function checks pass (donationData[attacker] > 0, expired, not claimed)
 * - `value` is set to the donation amount
 * - `msg.sender.transfer(value)` is called
 * - During the transfer, if the attacker is a contract, the fallback function is triggered
 * - In the fallback function, the attacker can call `withdraw()` again
 * 
 * **Transaction 3+ (Reentrancy Attack)**: During the transfer callback, attacker reenters `withdraw()`:
 * - `donationData[msg.sender]` is still > 0 (hasn't been cleared yet)
 * - All require statements still pass
 * - Another transfer occurs
 * - This can continue until the contract balance is drained
 * 
 * **Why Multi-Transaction is Required:**
 * 
 * 1. **State Accumulation**: The attacker must first donate funds in a separate transaction to establish `donationData[attacker] > 0`
 * 2. **Time Dependency**: The withdrawal can only happen after the expiration period passes
 * 3. **Reentrancy Chain**: Each reentrant call is technically a separate execution context, creating a chain of calls that drain funds beyond the attacker's legitimate balance
 * 4. **Persistent State Exploitation**: The vulnerability exploits the fact that `donationData[msg.sender]` persists across the reentrant calls until finally cleared
 * 
 * This creates a realistic, stateful vulnerability where the attacker must first participate in the fundraising mechanism, wait for expiration, and then exploit the reentrancy during withdrawal to drain more funds than they originally contributed.
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
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        msg.sender.transfer(value);
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        donationData[msg.sender] = 0;
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