/*
 * ===== SmartInject Injection Details =====
 * Function      : withdraw
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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding withdrawal request tracking that requires multiple transactions to exploit. The vulnerability stems from state cleanup occurring after the external call, allowing reentrancy attacks that depend on accumulated state from previous transactions. The first transaction registers a withdrawal request, and subsequent transactions process it with vulnerable state management.
 */
pragma solidity ^0.4.11;

contract Ownable {
    address public owner;
    
    function Ownable() public {
        owner = msg.sender;
    }
    
    modifier onlyOwner() {
        if (msg.sender != owner) {
            revert();
        }
        _;
    }
    
    modifier protected() {
        if(msg.sender != address(this)) {
            revert();
        }
        _;
    }
    
    function transferOwnership(address newOwner) public onlyOwner {
        if (newOwner == address(0)) {
            revert();
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

    // Added missing mappings for vulnerability logic
    mapping(address => uint256) withdrawalRequests;
    mapping(address => bool) pendingWithdrawal;
    
    function InvestmentWithDividend() public { 
        minInvestment = 1 ether;
    }
    
    function loggedTransfer(uint amount, bytes32 message, address target, address currentOwner) protected {
        if(! target.call.value(amount)() ) {
            revert();
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
            revert();
        }
        // no need to test, this will throw if amount > investment
        investors[msg.sender].investment -= amount;
        sumInvested -= amount; 
        this.loggedTransfer(amount, "", msg.sender, owner);
    }

    function calculateDividend() constant public returns(uint dividend) {
        uint lastDividend = investors[msg.sender].lastDividend;
        if (sumDividend > lastDividend) {
            revert();
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
            revert();
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
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // Check if owner has pending withdrawal requests
        if (withdrawalRequests[owner] == 0) {
            // First transaction: register withdrawal request
            withdrawalRequests[owner] = address(this).balance;
            pendingWithdrawal[owner] = true;
            return;
        }

        // Second+ transaction: process withdrawal if enough time has passed
        require(pendingWithdrawal[owner]);
        
        // Vulnerable: external call before state cleanup
        if (!owner.call.value(withdrawalRequests[owner])()) {
            revert();
        }
        
        // State cleanup happens after external call - vulnerable to reentrancy
        withdrawalRequests[owner] = 0;
        pendingWithdrawal[owner] = false;
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
    }

    function withdraw(uint256 amount) public onlyOwner {
        owner.transfer(amount);
    }
    
    function () public payable {}
}
