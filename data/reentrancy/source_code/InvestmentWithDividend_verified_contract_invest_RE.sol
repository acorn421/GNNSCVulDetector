/*
 * ===== SmartInject Injection Details =====
 * Function      : invest
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 2 findings
 * Total Found   : 4 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-benign (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to notify existing investors about investment updates. The vulnerability requires multiple transactions to exploit:
 * 
 * 1. **Initial State Setup (Transaction 1)**: An attacker must first become an investor by calling invest() with legitimate funds to establish their investor record (investors[msg.sender].investment > 0).
 * 
 * 2. **Exploitation Phase (Transaction 2+)**: In subsequent invest() calls, the external call msg.sender.call() is triggered before state updates. During this callback, the attacker can:
 *    - Re-enter invest() while the current transaction's state updates are pending
 *    - The re-entrant call sees the old state values (sumInvested, investors[msg.sender].investment)
 *    - Multiple investment amounts can be recorded with the same ETH value
 *    - Each re-entrant call further inflates the recorded investment balance
 * 
 * 3. **Multi-Transaction Dependency**: The vulnerability cannot be exploited in a single transaction because:
 *    - First transaction establishes the investor state required for the external call
 *    - Subsequent transactions trigger the vulnerable callback mechanism
 *    - The accumulated inflated investment balance from multiple transactions enables profitable exploitation through divest() or payDividend()
 * 
 * The external call appears as a realistic feature for notifying external contracts about investment updates, making it a subtle but dangerous vulnerability pattern commonly found in DeFi applications.
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
            // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
            // Notify external investment tracker before state updates
            if (investors[msg.sender].investment > 0) {
                // Call external contract for existing investors (potential reentrancy point)
                msg.sender.call(bytes4(keccak256("onInvestmentUpdate(uint256,uint256)")), investors[msg.sender].investment, msg.value);
            }
            
            // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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
        investors[msg.sender].investment -= amount;
        sumInvested -= amount; 
        this.loggedTransfer(amount, "", msg.sender, owner);
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