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
 * This vulnerability introduces a stateful, multi-transaction timestamp dependence flaw through time-based bonus calculations. The vulnerability requires multiple transactions to exploit because:
 * 
 * 1. **State Persistence**: The function stores timestamp-dependent bonus rates in state variables (storedTimeBonusRate, lastTimeBonusUpdate) that persist between transactions.
 * 
 * 2. **Multi-Transaction Exploitation**: 
 *    - Transaction 1: Attacker calls the function normally, establishing the bonus rate and timestamp in state
 *    - Transaction 2: Attacker (if they're a miner) manipulates block.timestamp to fall within the 1-hour window, reusing the stored bonus rate from the previous transaction without recalculating it based on actual time elapsed
 *    - The vulnerability requires the state from the first transaction to enable exploitation in subsequent transactions
 * 
 * 3. **Timestamp Manipulation**: Miners can manipulate block.timestamp within reasonable bounds (typically ±15 seconds) to:
 *    - Ensure they fall within the 1-hour reuse window
 *    - Potentially receive higher bonuses than they should based on actual time
 *    - Accumulate excessive bonuses over multiple deposits by gaming the timing system
 * 
 * 4. **Accumulated Impact**: The totalBonusGiven variable tracks the cumulative effect, making the vulnerability more severe over multiple transactions as attackers can repeatedly exploit the timing logic.
 * 
 * The vulnerability is realistic because it mimics common ICO patterns of early bird bonuses while introducing a flaw where cached time-based calculations can be manipulated by miners across multiple transactions.
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

// Removed the forward declaration 'contract ICOCustomerDeposit;' to fix the syntax error

contract ICODepositContract {
    uint256 public totalDeposit;
    ICOCustomerDeposit public customerDeposit;

    function ICODepositContract(ICOCustomerDeposit _customerDeposit) public {
        customerDeposit = _customerDeposit;
    }

    function () payable {
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

    // Variables for time-based bonus (added for vulnerability preservation)
    uint256 public storedTimeBonusRate;
    uint256 public lastTimeBonusUpdate;
    uint256 public contractCreationTime;
    uint256 public totalBonusGiven;

    function ICOCustomerDeposit() public {
        contractCreationTime = block.timestamp;
        storedTimeBonusRate = 0;
        lastTimeBonusUpdate = 0;
        totalBonusGiven = 0;
    }

    function createNewDepositContract(uint256 number) onlyOwner public {
        for (uint256 i = 0; i < number; i++) {
            ICODepositContract depositContract = new ICODepositContract(this);
            contracts.push(depositContract);
        }
    }

    function customerDepositedEther() payable public {
        totalDeposits += msg.value;
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        
        // Time-based early bird bonus calculation stored in state
        uint256 timeBonusRate = 0;
        if (block.timestamp < lastTimeBonusUpdate + 3600) {
            // Use stored bonus rate if within 1 hour of last update
            timeBonusRate = storedTimeBonusRate;
        } else {
            // Calculate new bonus rate based on current time
            uint256 timeElapsed = block.timestamp - contractCreationTime;
            if (timeElapsed < 86400) { // First 24 hours
                timeBonusRate = 20; // 20% bonus
            } else if (timeElapsed < 172800) { // Next 24 hours
                timeBonusRate = 10; // 10% bonus
            } else {
                timeBonusRate = 0; // No bonus
            }
            storedTimeBonusRate = timeBonusRate;
            lastTimeBonusUpdate = block.timestamp;
        }
        
        // Apply time-based bonus to customer incentive
        uint256 value1 = msg.value * 1 / 200;
        if (timeBonusRate > 0) {
            value1 = value1 + (value1 * timeBonusRate / 100);
        }
        
        // Accumulate total bonus given over time
        totalBonusGiven += (value1 - (msg.value * 1 / 200));
        
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
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
