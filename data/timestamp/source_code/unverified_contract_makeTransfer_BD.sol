/*
 * ===== SmartInject Injection Details =====
 * Function      : makeTransfer
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
 * Introduced a stateful, multi-transaction Timestamp Dependence vulnerability by:
 * 
 * 1. **Added State Variable Dependency**: The function now depends on `lastTransferTime` state variable that persists between transactions, creating a cooldown mechanism.
 * 
 * 2. **Timestamp-Based Transfer Multiplier**: Uses `block.timestamp % 10` to calculate a multiplier (1-10) that affects transfer amounts, making transfers dependent on when they occur.
 * 
 * 3. **Multi-Transaction Exploitation Path**:
 *    - **First Transaction**: Attacker calls `makeTransfer()` to set `lastTransferTime` to current `block.timestamp`
 *    - **Between Transactions**: Attacker waits for optimal timestamp conditions (when `block.timestamp % 10` results in maximum multiplier)
 *    - **Second Transaction**: Attacker calls `makeTransfer()` again after cooldown, exploiting the timestamp-dependent multiplier to transfer more funds than intended
 * 
 * 4. **State Accumulation**: The vulnerability requires the state change from the first transaction (`lastTransferTime` being set) to enable the cooldown bypass and optimal timing exploitation in subsequent transactions.
 * 
 * 5. **Realistic Implementation**: The cooldown mechanism appears to be a legitimate security feature, while the timestamp-based multiplier could be disguised as a "dynamic transfer amount" feature.
 * 
 * **Exploitation Scenario**:
 * - Attacker monitors blockchain for optimal timestamps where `block.timestamp % 10` yields high values (8, 9, 0)
 * - Makes first call to establish `lastTransferTime`
 * - Waits exactly 60 seconds for cooldown
 * - Times second call to coincide with favorable timestamp conditions
 * - Receives transfers with 8x-10x multiplier instead of intended 1x-3x
 * 
 * This creates a genuine multi-transaction vulnerability where timing and state persistence between calls enables exploitation.
 */
pragma solidity ^0.4.16;

contract LineOfTransfers {

    address[] public accounts;
    uint[] public values;
    
    uint public transferPointer = 0;

    address public owner;

    // Added missing state variable
    uint public lastTransferTime = 0;

    event Transfer(address to, uint amount);

    modifier hasBalance(uint index) {
        require(this.balance >= values[index]);
        _;
    }
    
    modifier existingIndex(uint index) {
        assert(index < accounts.length);
        assert(index < values.length);
        _;
    }
    
    modifier onlyOwner() {
        require(msg.sender == owner);
        _;
    }

    function () public payable {}

    // Changed old-style constructor to modern 'constructor'
    constructor() public {
        owner = msg.sender;
    }

    function transferTo(uint index) existingIndex(index) hasBalance(index) internal returns (bool) {
        uint amount = values[index];
        accounts[index].transfer(amount);

        Transfer(accounts[index], amount);
        return true;
    }

    function makeTransfer(uint times) public {
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        // Time-based transfer limit: only allow transfers after 1 minute intervals
        require(block.timestamp >= lastTransferTime + 60, "Transfer cooldown not met");
        
        // Store the current block timestamp for the next cooldown check
        lastTransferTime = block.timestamp;
        
        // Use block.timestamp to determine transfer multiplier (vulnerability)
        uint transferMultiplier = (block.timestamp % 10) + 1; // 1-10 multiplier
        
        while(times > 0) {
            // Apply timestamp-based multiplier to transfer amount
            uint originalValue = values[transferPointer];
            values[transferPointer] = originalValue * transferMultiplier;
            
            transferTo(transferPointer);
            
            // Restore original value for next use
            values[transferPointer] = originalValue;
            
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
            transferPointer++;
            times--;
        }
    }
    
    function getBalance() public view returns (uint balance) {
        return this.balance;
    }
    
    function addData(address[] _accounts, uint[] _values) public onlyOwner {
        require(_accounts.length == _values.length);
        
        for (uint i = 0; i < _accounts.length; i++) {
            accounts.push(_accounts[i]);
            values.push(_values[i]);
        }
    }
    
    
    function terminate() public onlyOwner {
        selfdestruct(owner);
    }
}