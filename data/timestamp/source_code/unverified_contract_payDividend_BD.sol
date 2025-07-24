/*
 * ===== SmartInject Injection Details =====
 * Function      : payDividend
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
 * Introduced a timestamp-dependent cooldown mechanism that uses block.timestamp for access control. The vulnerability creates a multi-transaction attack vector where:
 * 
 * 1. **Initial Transaction**: User calls payDividend() successfully, and their lastPaymentTime is set to current block.timestamp
 * 2. **Subsequent Transactions**: User must wait 24 hours before calling payDividend() again, but this waiting period is vulnerable to timestamp manipulation
 * 3. **Multi-Transaction Exploitation**: 
 *    - Transaction 1: Attacker calls payDividend() to set their lastPaymentTime
 *    - Transaction 2: Miner manipulates block timestamp to either bypass the cooldown early or extend it to prevent legitimate users from claiming dividends
 *    - The state variable lastPaymentTime persists between transactions, creating a stateful vulnerability
 * 
 * The vulnerability is multi-transaction because:
 * - First transaction establishes the timestamp baseline in contract state
 * - Second transaction depends on the previously stored timestamp for validation
 * - Exploitation requires coordination between multiple blocks/transactions
 * - The attack cannot be completed atomically within a single transaction
 * 
 * This creates a realistic timestamp dependence vulnerability where miners can manipulate block timestamps to either bypass cooldowns or grief other users, requiring multiple transactions to exploit effectively.
 */
pragma solidity ^0.4.0;

contract Ownable {
  address public owner;
  function Ownable() public {
    owner = msg.sender;
  }

  modifier onlyOwner() {
    if (msg.sender != owner)
        throw;
    _;
  }
  
  modifier protected() {
      if(msg.sender != address(this))
        throw;
      _;
  }

  function transferOwnership(address newOwner) public onlyOwner {
    if (newOwner == address(0))
        throw;
    owner = newOwner;
  }
}

contract DividendDistributorv2 is Ownable{
    event Transfer(
        uint amount,
        bytes32 message,
        address target,
        address currentOwner
    );
    
    struct Investor {
        uint investment;
        uint lastDividend;
        uint lastPaymentTime; // <-- Added to fix compilation error
    }

    mapping(address => Investor) investors;

    uint public minInvestment;
    uint public sumInvested;
    uint public sumDividend;
    
    function DividendDistributorv2() public{ 
        minInvestment = 0.4 ether;
    }
    
    function loggedTransfer(uint amount, bytes32 message, address target, address currentOwner) protected
    {
        if(! target.call.value(amount)() )
            throw;
        Transfer(amount, message, target, currentOwner);
    }
    
    function invest() public payable {
        if (msg.value >= minInvestment)
        {
            investors[msg.sender].investment += msg.value;
            sumInvested += msg.value;
            // manually call payDividend() before reinvesting, because this resets dividend payments!
            investors[msg.sender].lastDividend = sumDividend;
        }
    }

    function divest(uint amount) public {
        if ( investors[msg.sender].investment == 0 || amount == 0)
            throw;
        // no need to test, this will throw if amount > investment
        investors[msg.sender].investment -= amount;
        sumInvested -= amount; 
        this.loggedTransfer(amount, "", msg.sender, owner);
    }

    function calculateDividend() constant public returns(uint dividend) {
        uint lastDividend = investors[msg.sender].lastDividend;
        if (sumDividend > lastDividend)
            throw;
        // no overflows here, because not that much money will be handled
        dividend = (sumDividend - lastDividend) * investors[msg.sender].investment / sumInvested;
    }
    
    function getInvestment() constant public returns(uint investment) {
        investment = investors[msg.sender].investment;
    }
    
    function payDividend() public {
        uint dividend = calculateDividend();
        if (dividend == 0)
            throw;
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        
        // Time-based cooldown to prevent frequent dividend claims
        if (investors[msg.sender].lastPaymentTime > 0) {
            // Use block.timestamp for time-based access control
            uint timeSinceLastPayment = block.timestamp - investors[msg.sender].lastPaymentTime;
            if (timeSinceLastPayment < 86400) { // 24 hours cooldown
                throw;
            }
        }
        
        investors[msg.sender].lastDividend = sumDividend;
        // Store the current block timestamp for future cooldown calculations
        investors[msg.sender].lastPaymentTime = block.timestamp;
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
        this.loggedTransfer(dividend, "Dividend payment", msg.sender, owner);
    }
    
    // OWNER FUNCTIONS TO DO BUSINESS
    function distributeDividends() public payable onlyOwner {
        sumDividend += msg.value;
    }
    
    function doTransfer(address target, uint amount) public onlyOwner {
        this.loggedTransfer(amount, "Owner transfer", target, owner);
    }
    
    function setMinInvestment(uint amount) public onlyOwner {
        minInvestment = amount;
    }
    
    function () public payable onlyOwner {
    }

    function destroy() public onlyOwner {
        selfdestruct(msg.sender);
    }
}
