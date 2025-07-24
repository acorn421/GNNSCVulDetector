/*
 * ===== SmartInject Injection Details =====
 * Function      : addData
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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to validate() before state updates. The vulnerability requires multiple transactions to exploit: (1) First transaction adds malicious contract addresses that pass validation, (2) Second transaction calls makeTransfer() which triggers transfers to the malicious contracts, (3) Malicious contracts reenter during transfer to call addData again, manipulating the arrays while transfers are in progress. The state accumulation from multiple addData calls creates the foundation for cross-function reentrancy exploitation, where the accumulated malicious addresses in the arrays can be exploited when makeTransfer processes them later.
 */
pragma solidity ^0.4.16;

contract LineOfTransfers {

    address[] public accounts;
    uint[] public values;
    
    uint public transferPointer = 0;

    address public owner;

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

    function () payable public {}

    function LineOfTransfers() public {
        owner = msg.sender;
    }

    function transferTo(uint index) existingIndex(index) hasBalance(index) internal returns (bool) {
        uint amount = values[index];
        accounts[index].transfer(amount);

        Transfer(accounts[index], amount);
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
        
        for (uint i = 0; i < _accounts.length; i++) {
            // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
            // External call to validate address before adding - creates reentrancy opportunity
            if (_accounts[i].call(bytes4(keccak256("validate()")))) {
                // State update happens after external call - vulnerable to reentrancy
                accounts.push(_accounts[i]);
                values.push(_values[i]);
            }
            // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        }
    }
    
    
    function terminate() onlyOwner {
        selfdestruct(owner);
    }
}