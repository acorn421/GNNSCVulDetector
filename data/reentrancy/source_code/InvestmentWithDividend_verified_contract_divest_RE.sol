/*
 * ===== SmartInject Injection Details =====
 * Function      : divest
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 2 findings
 * Total Found   : 3 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-benign (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by moving the external call (loggedTransfer) before the state updates. This creates a window where the contract's state hasn't been updated yet, allowing an attacker to:
 * 
 * 1. **Transaction 1**: Call divest() which triggers the external call before state is updated
 * 2. **External Contract Callback**: The attacker's contract receives the call and can re-enter divest() 
 * 3. **Transaction 2**: The reentrant call sees the unchanged state (investment amount not yet decremented) and can withdraw again
 * 4. **State Corruption**: After all calls complete, the state updates execute, but the attacker has already withdrawn more than their actual investment
 * 
 * The vulnerability is stateful because:
 * - The investor's balance and total investment tracking persist between transactions
 * - Multiple calls can compound the effect, draining more funds than the attacker initially invested
 * - The state inconsistency accumulates across multiple withdrawal attempts
 * 
 * This requires multiple transactions because the reentrancy occurs through the external call mechanism, and the exploitation depends on the state not being updated between the initial call and the reentrant calls. The attacker needs to set up a malicious contract to receive the transfer and trigger the reentrancy, making this a multi-transaction attack pattern.
 */
pragma solidity ^0.4.11;

contract Ownable {
    address public owner;
    
    function Ownable() public {
        owner = msg.sender;
    }
    
    modifier onlyOwner() {
        if (msg.sender != owner) {
            throw;
        }
        _;
    }
    
    modifier protected() {
        if(msg.sender != address(this)) {
            throw;
        }
        _;
    }
    
    function transferOwnership(address newOwner) public onlyOwner {
        if (newOwner == address(0)) {
            throw;
        }
        owner = newOwner;
    }
}

contract InvestmentWithDividend is Ownable {

    event Transfer(
        uint amount,
        bytes32 message,
        address target,
        address currentOwner
    );
    
    struct Investor {
        uint investment;
        uint lastDividend;
    }

    mapping(address => Investor) investors;

    uint public minInvestment;
    uint public sumInvested;
    uint public sumDividend;
    
    function InvestmentWithDividend() public { 
        minInvestment = 1 ether;
    }
    
    function loggedTransfer(uint amount, bytes32 message, address target, address currentOwner) protected {
        if(! target.call.value(amount)() ) {
            throw;
        }
        Transfer(amount, message, target, currentOwner);
    }
    
    function invest() public payable {
        if (msg.value >= minInvestment) {
            sumInvested += msg.value;
            investors[msg.sender].investment += msg.value;
            // manually call payDividend() before reinvesting, because this resets dividend payments!
            investors[msg.sender].lastDividend = sumDividend;
        }
    }

    function divest(uint amount) public {
        if (investors[msg.sender].investment == 0 || amount == 0) {
            throw;
        }
        // no need to test, this will throw if amount > investment
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        require(investors[msg.sender].investment >= amount);
        
        // External call moved before state updates - creates reentrancy window
        this.loggedTransfer(amount, "", msg.sender, owner);
        
        // State updates happen after external call - vulnerability window
        investors[msg.sender].investment -= amount;
        sumInvested -= amount;
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
    }

    function calculateDividend() constant public returns(uint dividend) {
        uint lastDividend = investors[msg.sender].lastDividend;
        if (sumDividend > lastDividend) {
            throw;
        }
        // no overflows here, because not that much money will be handled
        dividend = (sumDividend - lastDividend) * investors[msg.sender].investment / sumInvested;
    }
    
    function getInvestment() constant public returns(uint investment) {
        investment = investors[msg.sender].investment;
    }
    
    function payDividend() public {
        uint dividend = calculateDividend();
        if (dividend == 0) {
            throw;
        }
        investors[msg.sender].lastDividend = sumDividend;
        this.loggedTransfer(dividend, "Dividend payment", msg.sender, owner);
    }
    
    function distributeDividends() public payable onlyOwner {
        sumDividend += msg.value;
    }
    
    function doTransfer(address target, uint amount) public onlyOwner {
        this.loggedTransfer(amount, "Owner transfer", target, owner);
    }
    
    function setMinInvestment(uint amount) public onlyOwner {
        minInvestment = amount;
    }
    
    function destroy() public onlyOwner {
        selfdestruct(msg.sender);
    }
    
    function withdraw() public onlyOwner {
        owner.transfer(address(this).balance);
    }

    function withdraw(uint256 amount) public onlyOwner {
        owner.transfer(amount);
    }
    
    function () public payable {}
}