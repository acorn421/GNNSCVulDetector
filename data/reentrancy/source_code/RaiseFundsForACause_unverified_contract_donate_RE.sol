/*
 * ===== SmartInject Injection Details =====
 * Function      : donate
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
 * 1. **Added State Tracking Variables**: Introduced `previousDonation` and `previousTotal` to store pre-update state values that are passed to the external callback.
 * 
 * 2. **External Call After State Updates**: Added a conditional external call to `msg.sender` using low-level `call()` function, which attempts to invoke `onDonationReceived()` callback on the donor's contract.
 * 
 * 3. **Reentrancy Window Creation**: The external call happens AFTER state updates (donationData, totalAmountRaised, numPayments) but the contract doesn't prevent reentrant calls.
 * 
 * 4. **Contract Detection**: Uses `msg.sender.code.length > 0` to detect if the sender is a contract before making the external call.
 * 
 * **Multi-Transaction Exploitation Mechanism:**
 * 
 * **Phase 1 - Setup (Transaction 1):**
 * - Attacker deploys a malicious contract that implements `onDonationReceived()`
 * - The malicious contract makes an initial legitimate donation to establish state
 * 
 * **Phase 2 - Exploitation (Transaction 2+):**
 * - Attacker's contract calls `donate()` with a small amount (e.g., 1 wei)
 * - The function updates state variables (donationData, totalAmountRaised, numPayments)
 * - The external call triggers the attacker's `onDonationReceived()` callback
 * - **Inside the callback**, the attacker can:
 *   - Call `donate()` again while the original call is still executing
 *   - Each reentrant call will see the UPDATED state from previous iterations
 *   - Build up accumulated donation credits over multiple reentrant calls
 *   - Inflate `totalAmountRaised` and `numPayments` counters
 * 
 * **Phase 3 - State Accumulation (Multiple Transactions):**
 * - The attacker can repeat this process across multiple transactions
 * - Each transaction allows multiple reentrant calls, building up inflated state
 * - The attacker accumulates donation credits that exceed their actual ETH contribution
 * - Later, the attacker can call `withdraw()` to extract more ETH than they contributed
 * 
 * **Why Multi-Transaction Exploitation is Required:**
 * 
 * 1. **Gas Limitations**: Deep reentrancy in a single transaction would hit gas limits, making multi-transaction exploitation necessary for maximum impact.
 * 
 * 2. **State Persistence**: The inflated `donationData[attacker]` persists between transactions, allowing the attacker to build up credits over time.
 * 
 * 3. **Realistic Constraints**: The contract's time-based expiration and minimum amount requirements create natural boundaries that favor multi-transaction exploitation.
 * 
 * 4. **Accumulated Effect**: Each transaction adds to the attacker's accumulated donation credits, creating a compounding effect that requires multiple transactions to reach significant monetary impact.
 * 
 * 5. **Detection Evasion**: Spreading the attack across multiple transactions makes it harder to detect than a single large-scale reentrancy attack.
 * 
 * The vulnerability is stateful because it depends on the persistent state changes in `donationData`, `totalAmountRaised`, and `numPayments` that accumulate across multiple transactions, making it impossible to exploit in a single atomic transaction.
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

        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // Store previous values for potential callback
        uint256 previousDonation = donationData[msg.sender];
        uint256 previousTotal = totalAmountRaised;
        
        // Update state after validation but before external call
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        donationData[msg.sender] += msg.value;
        totalAmountRaised += msg.value;
        numPayments += 1;
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // External call to notify donor about successful donation
        // This creates a reentrancy window where state is updated but effects can be duplicated
        if (isContract(msg.sender)) {
            // Call external contract to notify about donation
            // NOTE: This is the vulnerable external call
            bool success = msg.sender.call(
                bytes4(keccak256("onDonationReceived(uint256,uint256,uint256)")),
                msg.value,
                previousDonation,
                previousTotal
            );
            // Continue execution even if callback fails
        }
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
    }

    function isContract(address _addr) private view returns (bool) {
        uint256 length;
        assembly { length := extcodesize(_addr) }
        return length > 0;
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
