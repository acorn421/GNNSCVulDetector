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
 * Total Found   : 0 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding a pendingWithdrawal mechanism. The vulnerability requires multiple transactions to exploit:
 * 
 * **Transaction 1**: Sets up the pending withdrawal state (pendingWithdrawal = balance)
 * **Transaction 2+**: Actually performs the withdrawal with external call before state update
 * 
 * **Multi-Transaction Exploitation Process:**
 * 
 * 1. **Initial Setup Transaction**: Attacker calls withdraw() first time, which sets pendingWithdrawal = current contract balance. No funds are transferred yet.
 * 
 * 2. **Exploitation Transaction**: Attacker calls withdraw() again. Now pendingWithdrawal > 0, so the function enters the vulnerable branch where:
 *    - It stores the amount to withdraw
 *    - Makes external call to withdrawer.transfer(amount) 
 *    - Only AFTER the external call does it reset pendingWithdrawal = 0
 * 
 * 3. **Reentrancy Attack**: During the transfer() call in step 2, the attacker's contract can re-enter withdraw() again. Since pendingWithdrawal hasn't been reset yet (state update happens after external call), the attacker can withdraw multiple times.
 * 
 * **Why Multi-Transaction is Required:**
 * - The vulnerability cannot be exploited in a single transaction because the first call only sets up the pending state
 * - The actual vulnerable external call only happens on subsequent transactions when pendingWithdrawal > 0
 * - This creates a realistic scenario where state accumulates across transactions, making the vulnerability stateful and multi-transaction dependent
 * 
 * **Realistic Vulnerability Pattern:**
 * This mimics real-world withdrawal queue or multi-step withdrawal systems where the first transaction "prepares" the withdrawal and subsequent transactions execute it. The vulnerability is subtle and could realistically appear in production code attempting to implement a two-phase withdrawal system.
 */
pragma solidity ^0.4.24;

contract Bank {
    string public name = "bank";
    address public owner;
    address public withdrawer;
    uint public pendingWithdrawal; // Added missing state variable

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
        withdrawer = _withdrawer;

        return (true);
    }

    function withdraw()
        public
        returns (bool)
    {
        require(msg.sender == withdrawer);
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Check if this is part of a multi-transaction withdrawal sequence
        if (pendingWithdrawal > 0) {
            uint amount = pendingWithdrawal;
            // External call before state update - vulnerable to reentrancy
            withdrawer.transfer(amount);
            pendingWithdrawal = 0;  // State update after external call
        } else {
            // First transaction: set up pending withdrawal
            pendingWithdrawal = address(this).balance;
        }
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====

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
