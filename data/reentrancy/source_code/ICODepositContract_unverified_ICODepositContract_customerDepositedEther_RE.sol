/*
 * ===== SmartInject Injection Details =====
 * Function      : customerDepositedEther
 * Vulnerability : Reentrancy
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 0 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by:
 * 
 * 1. **Added State-Dependent Logic**: Created a bonus mechanism that depends on the accumulated totalDeposits across multiple transactions (triggers when totalDeposits > 10 ether)
 * 
 * 2. **Violated CEI Pattern**: Moved the external call (bonus payment) BEFORE the state update (totalDeposits += msg.value), creating a critical reentrancy window
 * 
 * 3. **Multi-Transaction Exploitation Path**:
 *    - Transaction 1-N: Multiple deposits accumulate totalDeposits until it exceeds 10 ether
 *    - Transaction N+1: Deposit triggers bonus eligibility check using OLD totalDeposits value
 *    - During bonus payment, attacker can reenter and exploit the stale state
 *    - Each reentrant call sees the same OLD totalDeposits value before it gets updated
 * 
 * 4. **Stateful Vulnerability**: The exploit requires building up state (totalDeposits) across multiple legitimate transactions before the vulnerability becomes exploitable
 * 
 * 5. **Realistic Attack Scenario**: An attacker waits for totalDeposits to grow through legitimate usage, then makes a deposit that triggers the bonus. During the bonus .send() call, they reenter multiple times, each time receiving bonus calculated on the OLD totalDeposits value before it gets updated with their current msg.value.
 * 
 * The vulnerability is NOT exploitable in a single transaction - it requires the accumulated state from previous transactions to reach the vulnerable condition, making it a perfect example of a stateful, multi-transaction reentrancy vulnerability.
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

    function createNewDepositContract(uint256 number) onlyOwner {
        for (uint256 i = 0; i < number; i++) {
            ICODepositContract depositContract = new ICODepositContract(this);
            contracts.push(depositContract);
        }
    }

    function customerDepositedEther() payable {
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // Check if customer has bonus eligibility based on accumulated deposits
        bool bonusEligible = false;
        if (totalDeposits > 10 ether) {
            bonusEligible = true;
        }
        
        // Calculate bonus before updating state (vulnerable to reentrancy)
        uint256 bonusAmount = 0;
        if (bonusEligible) {
            bonusAmount = totalDeposits * 5 / 1000; // 0.5% bonus based on total deposits
        }
        
        // External call BEFORE state update - creates reentrancy window
        if (bonusAmount > 0) {
            if (!msg.sender.send(bonusAmount)) throw;
        }
        
        // State update happens AFTER external call
        totalDeposits += msg.value;
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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