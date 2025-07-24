/*
 * ===== SmartInject Injection Details =====
 * Function      : setWithdrawer
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 1 findings
 * Total Found   : 1 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the previous withdrawer before updating the withdrawer state. This creates a classic Checks-Effects-Interactions pattern violation where the external call can re-enter the function and manipulate the contract state across multiple transactions.
 * 
 * **Specific Changes Made:**
 * 
 * 1. **Added External Call Before State Update**: Introduced `IWithdrawerNotifiable(withdrawer).onWithdrawerChanged(_withdrawer)` call that executes before the state variable `withdrawer` is updated.
 * 
 * 2. **Violated Checks-Effects-Interactions Pattern**: The external call happens before the state change, allowing the called contract to re-enter and observe/manipulate an inconsistent state.
 * 
 * 3. **Created State Dependency**: The vulnerability depends on the existing `withdrawer` state from previous transactions, making it inherently multi-transaction dependent.
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 
 * **Transaction 1 (Setup):**
 * - Owner calls `setWithdrawer(maliciousContract)` for the first time
 * - `withdrawer` is set to `maliciousContract`
 * - No external call happens since `withdrawer` was initially `address(0)`
 * 
 * **Transaction 2 (Exploitation):**
 * - Owner calls `setWithdrawer(newAddress)` 
 * - The function calls `maliciousContract.onWithdrawerChanged(newAddress)`
 * - Inside the callback, `maliciousContract` re-enters `setWithdrawer(attackerAddress)`
 * - Since `withdrawer` hasn't been updated yet, the malicious contract can:
 *   - Call `withdraw()` function (since it's still the current withdrawer)
 *   - Set itself as withdrawer again through reentrancy
 *   - Manipulate the final state through multiple reentrant calls
 * 
 * **Why Multi-Transaction Dependency is Essential:**
 * 
 * 1. **State Accumulation**: The vulnerability only exists when `withdrawer` is already set from a previous transaction (not `address(0)`)
 * 
 * 2. **Persistent State Manipulation**: The attack leverages the fact that `withdrawer` state persists between transactions and can be manipulated during the brief window where external calls occur
 * 
 * 3. **Sequential Dependency**: The exploit requires:
 *    - Transaction 1: Set initial withdrawer to malicious contract
 *    - Transaction 2: Trigger the vulnerable state change that enables reentrancy
 *    - During Transaction 2: Multiple reentrant calls can manipulate the persistent state
 * 
 * This creates a realistic, stateful reentrancy vulnerability that mirrors real-world patterns where contracts notify external parties about state changes, creating windows for reentrancy attacks that span multiple transactions.
 */
pragma solidity ^0.4.24;

interface IWithdrawerNotifiable {
    function onWithdrawerChanged(address _newWithdrawer) external;
}

contract Bank {
    string public name = "bank";
    address public owner;
    address public withdrawer;

    constructor()
        public
    {
        owner = msg.sender;
    }

    function()
        public
        payable
    {
        // do nothing
    }

    function deposit(address _addr)
        external
        payable
        returns (bool)
    {
        require(msg.value > 0, "Failed - zero deposits not allowed");
        return (true);
    }

    function migrationReceiver_setup()
        external
        returns (bool)
    {
        return (true);
    }

    function setWithdrawer(address _withdrawer)
        public
        returns (bool)
    {
        require(msg.sender == owner);
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Notify previous withdrawer about the change via external call
        if (withdrawer != address(0)) {
            // External call before state update - creates reentrancy vulnerability
            IWithdrawerNotifiable(withdrawer).onWithdrawerChanged(_withdrawer);
        }
        
        // State update happens after external call - vulnerable to reentrancy
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        withdrawer = _withdrawer;

        return (true);
    }

    function withdraw()
        public
        returns (bool)
    {
        require(msg.sender == withdrawer);
        withdrawer.transfer(address(this).balance);

        return (true);
    }

    function getContractBalance()
        public
        view
        returns (uint)
    {
        return (address(this).balance);
    }
}
