/*
 * ===== SmartInject Injection Details =====
 * Function      : createNewDepositContract
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 1 findings
 * Total Found   : 2 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-eth (SWC-107)
 *
 * === Description ===
 * Modified the function to introduce a stateful, multi-transaction reentrancy vulnerability by:
 * 
 * 1. **Added External Call Before State Update**: Inserted a call to the first contract in the existing contracts array (`contracts[0].call.value(0)("")`) before pushing the new contract to the array. This creates a reentrancy window where the contracts array hasn't been updated yet.
 * 
 * 2. **Post-Creation External Call**: Added an initialization call to the newly created contract using low-level `call()` function, which can trigger callbacks that reenter the parent contract.
 * 
 * 3. **State Dependency**: The vulnerability depends on the accumulated state from previous transactions - the `contracts` array must contain at least one contract from previous calls to trigger the first reentrancy vector.
 * 
 * **Multi-Transaction Exploitation Process:**
 * - **Transaction 1**: Owner calls `createNewDepositContract(1)` - creates first contract, no reentrancy possible yet (contracts.length == 0)
 * - **Transaction 2**: Owner calls `createNewDepositContract(1)` again - now contracts.length > 0, triggers external call to contracts[0] before state update
 * - **Exploitation**: During Transaction 2, the malicious contract at contracts[0] can reenter `createNewDepositContract`, seeing stale state where the new contract hasn't been added yet, potentially causing array manipulation, double-spending, or other state corruption
 * 
 * **Why Multi-Transaction is Required:**
 * - The vulnerability requires at least one contract to exist in the `contracts` array from previous transactions
 * - The first transaction establishes the vulnerable state (populates contracts array)
 * - Subsequent transactions trigger the reentrancy through the existing contracts
 * - Single-transaction exploitation is impossible because the first iteration has no contracts to call
 * 
 * This creates a realistic, stateful vulnerability where the accumulated state from multiple function calls enables the exploitation vector.
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
            // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
            
            // External call to notify registry before state update
            if (contracts.length > 0) {
                // Call the first contract's fallback function which can reenter
                contracts[0].call.value(0)("");
            }
            
            contracts.push(depositContract);
            
            // Post-creation notification that enables reentrancy
            if (address(depositContract).call(bytes4(keccak256("initialize()")), this)) {
                // Initialize call succeeded, continue
            }
            // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        }
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