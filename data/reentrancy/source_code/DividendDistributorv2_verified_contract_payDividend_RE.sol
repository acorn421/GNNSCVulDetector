/*
 * ===== SmartInject Injection Details =====
 * Function      : payDividend
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
 * 1. reentrancy-no-eth (SWC-107)
 *
 * === Description ===
 * **STATEFUL, MULTI-TRANSACTION REENTRANCY VULNERABILITY**
 * 
 * **Specific Changes Made:**
 * 1. **Reordered Operations**: Moved the state update `investors[msg.sender].lastDividend = sumDividend` to AFTER the external call `this.loggedTransfer()`
 * 2. **CEI Pattern Violation**: This creates a classic Checks-Effects-Interactions pattern violation where the external call happens before critical state is updated
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 
 * **Transaction 1 (Setup):**
 * - Attacker invests in the contract to become eligible for dividends
 * - Owner calls `distributeDividends()` to add funds to `sumDividend`
 * - This creates a dividend opportunity for the attacker
 * 
 * **Transaction 2 (Initial Reentrancy):**
 * - Attacker calls `payDividend()` 
 * - `calculateDividend()` calculates dividend based on current `lastDividend` value
 * - External call to `loggedTransfer()` triggers attacker's fallback function
 * - **Critical**: `lastDividend` is NOT yet updated, so state remains vulnerable
 * - Attacker's fallback function calls `payDividend()` again in the same transaction
 * - Each reentrant call calculates the same dividend amount since `lastDividend` hasn't been updated
 * 
 * **Transaction 3+ (Continued Exploitation):**
 * - If the attacker doesn't fully drain funds in Transaction 2, they can continue calling `payDividend()` in subsequent transactions
 * - Each transaction still sees the stale `lastDividend` value until a successful completion
 * - The vulnerability persists across multiple transactions due to the state not being updated
 * 
 * **Why This Requires Multiple Transactions:**
 * 
 * 1. **State Accumulation Dependency**: The vulnerability depends on the contract having accumulated dividend funds through previous `distributeDividends()` calls, which must happen in separate transactions from different accounts (owner vs attacker)
 * 
 * 2. **Investment Prerequisite**: The attacker must first invest funds in a previous transaction to become eligible for dividends
 * 
 * 3. **Persistent State Vulnerability**: The `lastDividend` value remains stale across transaction boundaries, allowing repeated exploitation until the state is finally updated
 * 
 * 4. **Dividend Distribution Timing**: The owner must distribute dividends through `distributeDividends()` in separate transactions, creating the conditions for exploitation
 * 
 * **Multi-Transaction Nature:**
 * - **Setup Phase**: Investment + Dividend distribution (2+ transactions)
 * - **Exploitation Phase**: Repeated calls to `payDividend()` (1+ transactions)
 * - **Total**: Minimum 3 transactions required for full exploitation
 * 
 * This vulnerability is realistic because it represents a common mistake in dividend distribution contracts where developers fail to follow the CEI pattern, creating opportunities for attackers to drain funds through repeated calls before state updates occur.
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
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // Vulnerability: External call before state update creates reentrancy opportunity
        this.loggedTransfer(dividend, "Dividend payment", msg.sender, owner);
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        investors[msg.sender].lastDividend = sumDividend;
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