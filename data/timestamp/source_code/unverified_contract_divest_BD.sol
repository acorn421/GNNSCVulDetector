/*
 * ===== SmartInject Injection Details =====
 * Function      : divest
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 2 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Introduced a timestamp-dependent early withdrawal penalty system that creates a stateful, multi-transaction vulnerability. The vulnerability exploits the use of block.timestamp for penalty calculations and repurposes the lastDividend field to store timing information. This creates multiple attack vectors:
 * 
 * 1. **Timestamp Manipulation Attack**: Miners can manipulate block.timestamp to reduce or eliminate penalties across multiple transactions
 * 2. **State Poisoning Attack**: Attackers can manipulate their lastDividend timestamp through strategic dividend payments, then exploit the timestamp dependency in subsequent divest calls
 * 3. **Cross-Transaction Timing Attack**: The vulnerability requires building up investment state over time, then timing multiple divest transactions to exploit timestamp weaknesses
 * 
 * The multi-transaction nature is enforced because:
 * - Users must first invest() to build up investment state
 * - The lastDividend timestamp must be established through prior transactions
 * - Penalty calculations depend on the accumulated time difference between transactions
 * - Optimal exploitation requires coordinating multiple divest calls with timestamp manipulation
 * 
 * This creates a realistic vulnerability where the penalty system can be gamed through timestamp manipulation across multiple blocks, making it impossible to exploit in a single transaction.
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
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        
        // Time-based early withdrawal penalty system
        uint investmentAge = block.timestamp - investors[msg.sender].lastDividend;
        uint penaltyRate = 0;
        
        // Calculate penalty based on timestamp
        if (investmentAge < 30 days) {
            penaltyRate = 50; // 5% penalty for early withdrawal
        } else if (investmentAge < 90 days) {
            penaltyRate = 20; // 2% penalty for medium-term withdrawal
        }
        
        // Apply penalty calculation using block.timestamp
        uint penalty = (amount * penaltyRate) / 1000;
        uint netAmount = amount - penalty;
        
        // Store last divest timestamp for future calculations
        investors[msg.sender].lastDividend = block.timestamp;
        
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
        // no need to test, this will throw if amount > investment
        investors[msg.sender].investment -= amount;
        sumInvested -= amount; 
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        
        // Transfer net amount after penalty
        this.loggedTransfer(netAmount, "", msg.sender, owner);
        
        // Transfer penalty to owner if applicable
        if (penalty > 0) {
            this.loggedTransfer(penalty, "Early withdrawal penalty", owner, owner);
        }
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
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