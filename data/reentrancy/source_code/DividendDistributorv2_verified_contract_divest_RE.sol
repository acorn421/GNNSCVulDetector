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
 * This modification introduces a stateful, multi-transaction reentrancy vulnerability by:
 * 
 * 1. **Reordering Operations**: Moving the external call (`this.loggedTransfer`) BEFORE the state updates, violating the Checks-Effects-Interactions pattern.
 * 
 * 2. **Multi-Transaction Exploitation Path**: 
 *    - Transaction 1: Attacker calls `divest(amount)` → external call executes → callback can call `divest()` again before state is updated
 *    - Transaction 2+: Subsequent reentrancy calls can continue draining funds since original investment balance hasn't been decremented yet
 *    - The vulnerability requires multiple transactions because each reentrant call must complete its external transfer before the next one can begin
 * 
 * 3. **Stateful Vulnerability**: The exploit depends on the persistent state of `investors[msg.sender].investment` and `sumInvested` not being updated until after the external call completes. This creates a window where multiple calls can reference the same unchanged investment balance.
 * 
 * 4. **Realistic Attack Vector**: An attacker can deploy a malicious contract that implements a fallback function. When `loggedTransfer` calls `target.call.value(amount)()`, it triggers the attacker's fallback, which can call `divest()` again before the original state updates occur.
 * 
 * 5. **Multi-Transaction Nature**: The vulnerability requires at least 2 separate message calls (original + reentrant) to exploit, with the reentrant call being able to reference stale state from before the first transaction's state updates were applied.
 * 
 * This creates a realistic reentrancy vulnerability where an attacker can drain more funds than their actual investment balance through carefully orchestrated multi-transaction attacks.
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
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Store pending withdrawal state before external call
        uint pendingAmount = amount;
        
        // Process external call BEFORE state updates to enable reentrancy
        this.loggedTransfer(pendingAmount, "", msg.sender, owner);
        
        // State updates occur after external call - vulnerable to reentrancy
        investors[msg.sender].investment -= amount;
        sumInvested -= amount;
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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
        investors[msg.sender].lastDividend = sumDividend;
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