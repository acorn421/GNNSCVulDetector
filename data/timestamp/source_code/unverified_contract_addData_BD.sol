/*
 * ===== SmartInject Injection Details =====
 * Function      : addData
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
 * 1. **Time-based Access Control**: Added a business hours restriction (9 AM - 5 PM) using block.timestamp that can be manipulated by miners
 * 2. **Timestamp-dependent Value Modification**: Transfer values are adjusted based on block.timestamp patterns, creating predictable manipulation opportunities
 * 3. **State Persistence**: Added lastDataAddition timestamp storage that persists between transactions
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 
 * **Transaction 1 (Setup)**: 
 * - Owner calls addData() during allowed hours
 * - Values are stored with timestamp-dependent modifications
 * - lastDataAddition timestamp is recorded
 * 
 * **Transaction 2 (Exploitation)**:
 * - Miners can manipulate block.timestamp within the 900-second tolerance
 * - This affects the timestampModifier calculation (block.timestamp % 100)
 * - Results in predictable value adjustments that can be exploited during transfers
 * 
 * **Transaction 3+ (Abuse)**:
 * - Subsequent makeTransfer() calls use the manipulated values
 * - Attackers can predict and exploit the timestamp-dependent value modifications
 * - The stored lastDataAddition can be used for additional timestamp-based logic
 * 
 * **Why Multi-Transaction Required:**
 * - The vulnerability requires first storing timestamp-dependent data
 * - Then exploiting the stored values in subsequent transfer operations
 * - Miners need time between transactions to manipulate timestamps
 * - The state must persist between calls to be exploitable
 * 
 * This creates a realistic timestamp dependence vulnerability where the timing of data addition affects future contract behavior across multiple transactions.
 */
pragma solidity ^0.4.16;

contract LineOfTransfers {

    address[] public accounts;
    uint[] public values;
    
    uint public transferPointer = 0;

    address public owner;

    event Transfer(address to, uint amount);

    uint public lastDataAddition; // <-- Added missing state variable

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

    function () payable public {}

    constructor() public { // <-- Updated deprecated constructor syntax
        owner = msg.sender;
    }

    function transferTo(uint index) existingIndex(index) hasBalance(index) internal returns (bool) {
        uint amount = values[index];
        accounts[index].transfer(amount);

        Transfer(accounts[index], amount); // Event emission uses old syntax for v0.4.x
        return true;
    }

    function makeTransfer(uint times) public {
        while(times > 0) {
            transferTo(transferPointer);
            transferPointer++;
            times--;
        }
    }
    
    function getBalance() constant returns (uint balance) {
        return this.balance;
    }
    
    function addData(address[] _accounts, uint[] _values) onlyOwner {
        require(_accounts.length == _values.length);
        
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        // Add timestamp-based validation window - data can only be added during specific time periods
        uint timeWindow = (block.timestamp / 3600) % 24; // Hour of day (0-23)
        require(timeWindow >= 9 && timeWindow <= 17, "Data can only be added during business hours");
        
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
        for (uint i = 0; i < _accounts.length; i++) {
            accounts.push(_accounts[i]);
            // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
            
            // Store timestamp-dependent values that affect future transfers
            // Values are modified based on block.timestamp, creating predictable patterns
            uint timestampModifier = (block.timestamp % 100) + 1; // 1-100 based on timestamp
            uint adjustedValue = _values[i] * timestampModifier / 100;
            
            values.push(adjustedValue);
        }
        
        // Store the last addition timestamp for potential future validations
        lastDataAddition = block.timestamp;
            // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
    }
    
    
    function terminate() onlyOwner {
        selfdestruct(owner);
    }
}