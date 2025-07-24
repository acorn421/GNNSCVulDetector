/*
 * ===== SmartInject Injection Details =====
 * Function      : transferOwnership
 * Vulnerability : Reentrancy
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
 * **Specific Changes Made:**
 * 
 * 1. **Added External Call After State Update**: Introduced a callback mechanism that notifies the new owner about the ownership transfer via `newOwner.call()` after the ownership state has already been changed.
 * 
 * 2. **Violation of Checks-Effects-Interactions Pattern**: The external call occurs after the critical state modification (`owner = newOwner`), creating a reentrancy window.
 * 
 * 3. **Callback Mechanism**: Added realistic functionality where the new owner contract can be notified about receiving ownership, which is a common pattern in production contracts.
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 
 * **Transaction 1 (Setup):**
 * - Attacker deploys a malicious contract that will become the new owner
 * - The malicious contract implements `onOwnershipReceived()` function
 * - Attacker calls `transferOwnership(maliciousContract)` from current owner account
 * 
 * **Transaction 2 (Exploitation):**
 * - During the callback in Transaction 1, the malicious contract's `onOwnershipReceived()` function is triggered
 * - The malicious contract can now perform reentrant calls back to the main contract
 * - Since ownership has already been transferred, the malicious contract can:
 *   - Call other owner-only functions while in the callback
 *   - Potentially transfer ownership again to another address
 *   - Manipulate other contract state before the original transaction completes
 * 
 * **Why Multi-Transaction Exploitation is Required:**
 * 
 * 1. **State Persistence**: The vulnerability depends on the `owner` state being persistently changed between transactions. The first transaction establishes the malicious contract as owner, enabling subsequent exploitation.
 * 
 * 2. **Accumulated Authority**: The malicious contract gains owner privileges that persist across transactions, allowing it to exploit these privileges in subsequent calls.
 * 
 * 3. **Callback Timing**: The external call provides an opportunity for the new owner to immediately act on their newfound authority while still within the context of the ownership transfer.
 * 
 * 4. **Cross-Transaction State Dependency**: The vulnerability becomes more dangerous over multiple transactions as the malicious owner can:
 *    - Set up additional attack vectors in subsequent transactions
 *    - Modify contract state in ways that compound the initial reentrancy
 *    - Use the persistent ownership to access other owner-only functions
 * 
 * This creates a realistic reentrancy vulnerability where the external call after state change allows the new owner to immediately exploit their authority, and the persistent nature of ownership enables ongoing multi-transaction attacks.
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
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Notify new owner about ownership transfer
        if (newOwner != address(0)) {
            // External call to new owner's contract after state change
            newOwner.call(bytes4(keccak256("onOwnershipReceived(address)")), owner);
        }
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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