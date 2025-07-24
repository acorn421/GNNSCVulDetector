/*
 * ===== SmartInject Injection Details =====
 * Function      : deposit
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
 * 1. reentrancy-benign (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by:
 * 
 * 1. **Added State Tracking**: Introduced userBalances mapping to track individual user deposits, creating persistent state between transactions
 * 2. **External Call Before State Finalization**: Added callback to _addr before updating the contract_balance state variable
 * 3. **CEI Pattern Violation**: The external call occurs after partial state updates (userBalances) but before final state updates (contract_balance)
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * - **Transaction 1**: Legitimate user deposits funds, building up userBalances[maliciousContract] 
 * - **Transaction 2**: Malicious contract calls deposit() again during the callback, exploiting the inconsistent state where userBalances is updated but contract_balance is not yet finalized
 * - **Accumulated State Dependency**: The vulnerability relies on the accumulated userBalances from previous transactions to enable exploitation
 * 
 * **Why Multi-Transaction Required:**
 * 1. **State Accumulation**: The exploit depends on accumulated balances from previous deposits
 * 2. **Callback Dependency**: The malicious contract must implement onDepositReceived() callback to trigger reentrancy
 * 3. **Sequential Exploitation**: First transaction sets up the vulnerable state, second transaction exploits it during callback
 * 4. **Persistent State Changes**: The userBalances mapping persists between transactions, enabling the stateful vulnerability
 * 
 * This creates a realistic vulnerability where the callback mechanism for deposit notifications allows reentrancy exploitation that depends on accumulated state from multiple transactions.
 */
pragma solidity ^0.4.24;

contract Bank {
    string public name = "bank";
    address public owner;
    address public withdrawer;
    
    // Added missing state variable declarations
    mapping(address => uint256) public userBalances;
    uint256 public contract_balance;

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
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Add accumulated balance tracking for users
        userBalances[_addr] += msg.value;
        
        // External call to notify deposit callback before finalizing state
        if (_addr.call.value(0)(bytes4(keccak256("onDepositReceived(uint256)")), msg.value)) {
            // Callback succeeded, continue processing
        }
        
        // Update total contract balance after external call
        contract_balance += msg.value;
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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