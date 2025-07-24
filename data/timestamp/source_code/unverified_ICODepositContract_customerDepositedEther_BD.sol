/*
 * ===== SmartInject Injection Details =====
 * Function      : customerDepositedEther
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 1 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Introduced a stateful, multi-transaction timestamp dependence vulnerability that combines time-based bonus calculations with accumulated state tracking. The vulnerability requires multiple deposits across different time windows to exploit effectively.
 * 
 * **Specific Changes Made:**
 * 
 * 1. **Time-based Bonus Multiplier**: Added logic that doubles incentive payments during specific time windows (1 minute every 5 minutes) based on `block.timestamp % 300 < 60`
 * 
 * 2. **Milestone Timestamp Storage**: Introduced `lastMilestoneTime` state variable that gets updated when `totalDeposits` reaches multiples of 10 ether, creating persistent state between transactions
 * 
 * 3. **Progressive Fee Reduction**: Added fee reduction logic that activates only when accumulated deposits exceed 50 ether AND more than 1 hour has passed since the last milestone
 * 
 * **Multi-Transaction Exploitation Scenarios:**
 * 
 * 1. **Bonus Window Exploitation**: Attackers can monitor the timestamp patterns and make strategic deposits during the "lucky" 1-minute windows to double their incentive payments
 * 
 * 2. **Milestone Manipulation**: Attackers can time their deposits to:
 *    - Reach milestone thresholds (10 ether multiples) at strategic timestamps
 *    - Wait for the 1-hour delay to exploit fee reductions on subsequent deposits
 *    - Coordinate multiple smaller deposits to accumulate favorable timing conditions
 * 
 * 3. **Compound Exploitation**: The most profitable attack requires:
 *    - Transaction 1: Deposit during bonus window to set favorable milestone timestamp
 *    - Transaction 2: Wait 1+ hours, then deposit ≥50 ether total to trigger fee reduction
 *    - Transaction 3: Make additional deposits combining bonus timing + fee reduction
 * 
 * **Why Multiple Transactions Are Required:**
 * 
 * - **State Accumulation**: The `totalDeposits` variable must accumulate across multiple calls to reach the 50 ether threshold
 * - **Time Persistence**: The `lastMilestoneTime` must be set in one transaction and used in subsequent transactions after the 1-hour delay
 * - **Timing Coordination**: Optimal exploitation requires coordinating deposits across multiple time windows and waiting periods
 * - **Compound Benefits**: Maximum profit requires combining bonus multipliers with fee reductions across sequential transactions
 * 
 * This creates a realistic ICO scenario where timing-based bonuses and progressive fee structures are common, but the reliance on manipulable block timestamps creates exploitable vulnerabilities.
 */
pragma solidity ^0.4.8;

// ----------------------------------------------------------------------------------------------
// Unique ICO deposit contacts for customers to deposit ethers that are sent to different
// wallets
//
// Enjoy. (c) Bok Consulting Pty Ltd & Incent Rewards 2017. The MIT Licence.
// ----------------------------------------------------------------------------------------------

contract Owned {
    address public owner;
    event OwnershipTransferred(address indexed _from, address indexed _to);

    function Owned() public {
        owner = msg.sender;
    }

    modifier onlyOwner {
        if (msg.sender != owner) throw;
        _;
    }

    function transferOwnership(address newOwner) onlyOwner public {
        OwnershipTransferred(owner, newOwner);
        owner = newOwner;
    }
}

contract ICODepositContract {
    uint256 public totalDeposit;
    ICOCustomerDeposit public customerDeposit;

    function ICODepositContract(ICOCustomerDeposit _customerDeposit) public {
        customerDeposit = _customerDeposit;
    }

    function () payable public {
        totalDeposit += msg.value;
        customerDeposit.customerDepositedEther.value(msg.value)();
    }
}

contract ICOCustomerDeposit is Owned {
    uint256 public totalDeposits;
    ICODepositContract[] public contracts;

    uint256 public lastMilestoneTime;

    event Deposit(address indexed _from, uint _value);

    // Define destination addresses
    // 0.5%
    address incentToCustomer = 0xa5f93F2516939d592f00c1ADF0Af4ABE589289ba;
    // 0.5%
    address icoFees = 0x38671398aD25461FB446A9BfaC2f4ED857C86863;
    // 99%
    address icoClientWallet = 0x994B085D71e0f9a7A36bE4BE691789DBf19009c8;

    function createNewDepositContract(uint256 number) onlyOwner public {
        for (uint256 i = 0; i < number; i++) {
            ICODepositContract depositContract = new ICODepositContract(this);
            contracts.push(depositContract);
        }
    }

    function customerDepositedEther() public payable {
        totalDeposits += msg.value;
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        
        // Time-based bonus calculation - vulnerable to timestamp manipulation
        uint256 bonusMultiplier = 1;
        if (block.timestamp % 300 < 60) { // 1 minute window every 5 minutes
            bonusMultiplier = 2; // Double bonus during "lucky" time windows
        }
        
        // Store timing information for accumulated bonus tracking
        if (totalDeposits % (10 ether) == 0) {
            // Milestone reached - store timestamp for future calculations
            lastMilestoneTime = block.timestamp;
        }
        
        // Calculate fees with time-based modifiers
        uint256 value1 = msg.value * bonusMultiplier / 200;
        if (!incentToCustomer.send(value1)) throw;
        
        // Progressive fee reduction based on accumulated deposits and timing
        uint256 feeReduction = 0;
        if (totalDeposits >= 50 ether && block.timestamp > lastMilestoneTime + 1 hours) {
            feeReduction = msg.value / 400; // 0.25% reduction for large accumulated deposits
        }
        
        uint256 value2 = (msg.value * 1 / 200) - feeReduction;
        if (!icoFees.send(value2)) throw;
        
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
        uint256 value3 = msg.value - value1 - value2;
        if (!icoClientWallet.send(value3)) throw;
        Deposit(msg.sender, msg.value);
    }

    // Prevent accidental sending of ethers
    function () public {
        throw;
    }
}
