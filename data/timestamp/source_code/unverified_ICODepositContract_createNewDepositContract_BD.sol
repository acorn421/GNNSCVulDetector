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
 * This modification introduces a stateful, multi-transaction Timestamp Dependence vulnerability by implementing time-based rate limiting for contract creation. The vulnerability manifests through:
 * 
 * 1. **Timestamp-Dependent Access Control**: The function uses `block.timestamp` to enforce time windows for contract creation, making it dependent on miner-manipulatable timestamps.
 * 
 * 2. **Stateful Time Tracking**: The `lastContractCreationTime` state variable persists between transactions, creating a stateful vulnerability that accumulates across multiple calls.
 * 
 * 3. **Multi-Transaction Exploitation**: 
 *    - **Transaction 1**: Attacker calls the function to set initial `lastContractCreationTime`
 *    - **Transaction 2+**: Attacker collaborates with miners to manipulate `block.timestamp` in subsequent transactions to bypass time restrictions and create more contracts than intended
 * 
 * 4. **Vulnerable Logic**: The function calculates `maxAllowedContracts` based on elapsed time, which can be manipulated by miners adjusting timestamps by up to ~900 seconds (15 minutes) without other nodes rejecting the block.
 * 
 * 5. **Exploitation Scenario**: An attacker can:
 *    - Call the function in Transaction 1 to establish baseline time
 *    - In Transaction 2, work with miners to set `block.timestamp` to a future value, making `timeElapsed` larger
 *    - This increases `maxAllowedContracts`, allowing creation of more contracts than the time-based rate limiting intended
 *    - The vulnerability requires multiple transactions because the state must be established first, then exploited in subsequent calls
 * 
 * The vulnerability is realistic because time-based access controls are common in ICO contracts, and the timestamp manipulation requires coordination across multiple blocks/transactions to be effective.
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

    function Owned() {
        owner = msg.sender;
    }

    modifier onlyOwner {
        if (msg.sender != owner) throw;
        _;
    }

    function transferOwnership(address newOwner) onlyOwner {
        OwnershipTransferred(owner, newOwner);
        owner = newOwner;
    }
}

contract ICODepositContract {
    uint256 public totalDeposit;
    ICOCustomerDeposit public customerDeposit;

    function ICODepositContract(ICOCustomerDeposit _customerDeposit) {
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

    // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
uint256 public lastContractCreationTime;
    uint256 public creationTimeWindow = 300; // 5 minutes in seconds
    
    function createNewDepositContract(uint256 number) onlyOwner {
        // Time-based access control using block.timestamp
        if (lastContractCreationTime == 0) {
            lastContractCreationTime = block.timestamp;
        }
        
        // Allow creation only if enough time has passed OR if it's within the initial window
        require(block.timestamp >= lastContractCreationTime + creationTimeWindow || 
                block.timestamp <= lastContractCreationTime + creationTimeWindow);
        
        // Calculate maximum allowed contracts based on time elapsed
        uint256 timeElapsed = block.timestamp - lastContractCreationTime;
        uint256 maxAllowedContracts = 1 + (timeElapsed / creationTimeWindow);
        
        // Vulnerable: Using block.timestamp for critical business logic
        if (contracts.length + number > maxAllowedContracts) {
            number = maxAllowedContracts - contracts.length;
        }
        
// ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
        for (uint256 i = 0; i < number; i++) {
            ICODepositContract depositContract = new ICODepositContract(this);
            contracts.push(depositContract);
        }
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        
        // Update the last creation time for future calls
        lastContractCreationTime = block.timestamp;
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
    }

    function customerDepositedEther() payable {
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
    function () {
        throw;
    }
}