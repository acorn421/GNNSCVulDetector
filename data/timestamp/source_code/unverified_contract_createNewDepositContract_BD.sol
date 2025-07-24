/*
 * ===== SmartInject Injection Details =====
 * Function      : createNewDepositContract
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
 * Introduced a stateful, multi-transaction timestamp dependence vulnerability by implementing time-based contract creation limits that persist across transactions. The vulnerability requires multiple transactions to exploit effectively:
 * 
 * **Changes Made:**
 * 1. Added time-based daily limits using `block.timestamp / 86400` for period calculation
 * 2. Introduced state variables `lastCreationPeriod`, `contractsCreatedToday`, and `lastCreationTimestamp` to track creation activity
 * 3. Made daily limits dynamic based on `block.timestamp % 100`, creating manipulation opportunities
 * 4. Implemented partial creation logic that can create inconsistent states
 * 
 * **Multi-Transaction Exploitation:**
 * 1. **Transaction 1**: Owner calls function normally, establishing initial state and consuming some daily quota
 * 2. **Transaction 2**: Miner manipulates timestamp to either:
 *    - Reset daily counter by advancing to next "day" (timestamp manipulation)
 *    - Increase daily limit through the modulo operation
 *    - Create timing windows for maximum contract creation
 * 
 * **Why Multiple Transactions Required:**
 * - The vulnerability depends on accumulated state (`contractsCreatedToday`) that persists between calls
 * - Miners need to observe current state before deciding on timestamp manipulation strategy
 * - Maximum exploitation requires multiple calls to fully abuse the dynamic daily limits
 * - The reset mechanism only triggers on subsequent calls, not within the same transaction
 * 
 * **Exploitation Scenarios:**
 * 1. **Quota Bypass**: Miner manipulates timestamp to reset daily counter across multiple transactions
 * 2. **Limit Inflation**: Miner sets timestamp to maximize the modulo-based daily limit
 * 3. **Timing Attack**: Coordinate multiple transactions with specific timestamp values to create maximum contracts
 * 
 * This creates a realistic vulnerability where miners can manipulate block timestamps across multiple transactions to bypass intended contract creation limits.
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

    event Deposit(address indexed _from, uint _value);

    // Define destination addresses
    // 0.5%
    address incentToCustomer = 0xa5f93F2516939d592f00c1ADF0Af4ABE589289ba;
    // 0.5%
    address icoFees = 0x38671398aD25461FB446A9BfaC2f4ED857C86863;
    // 99%
    address icoClientWallet = 0x994B085D71e0f9a7A36bE4BE691789DBf19009c8;

    // Added missing state variables
    uint256 public lastCreationPeriod;
    uint256 public contractsCreatedToday;
    uint256 public lastCreationTimestamp;

    function createNewDepositContract(uint256 number) onlyOwner public {
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        // Time-based contract creation limits with state persistence
        uint256 currentPeriod = block.timestamp / 86400; // Daily periods
        
        // Initialize tracking for first use
        if (lastCreationPeriod == 0) {
            lastCreationPeriod = currentPeriod;
            contractsCreatedToday = 0;
        }
        
        // Reset counter for new day
        if (currentPeriod > lastCreationPeriod) {
            contractsCreatedToday = 0;
            lastCreationPeriod = currentPeriod;
        }
        
        // Dynamic daily limits based on timestamp manipulation
        uint256 dailyLimit = 10 + (block.timestamp % 100); // Vulnerable: miners can manipulate
        
        // Check if creation would exceed daily limit
        if (contractsCreatedToday + number > dailyLimit) {
            // Partial creation allowed - creates inconsistent state
            number = dailyLimit - contractsCreatedToday;
        }
        
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
        for (uint256 i = 0; i < number; i++) {
            ICODepositContract depositContract = new ICODepositContract(this);
            contracts.push(depositContract);
        }
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        
        // Update state - critical for multi-transaction exploitation
        contractsCreatedToday += number;
        lastCreationTimestamp = block.timestamp;
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
    }

    function customerDepositedEther() payable public {
        totalDeposits += msg.value;
        uint256 value1 = msg.value * 1 / 200;
        if (!incentToCustomer.send(value1)) throw;
        uint256 value2 = msg.value * 1 / 200;
        if (!icoFees.send(value2)) throw;
        uint256 value3 = msg.value - value1 - value2;
        if (!icoClientWallet.send(value3)) throw;
        Deposit(msg.sender, msg.value);
    }

    // Prevent accidental sending of ethers
    function () public {
        throw;
    }
}