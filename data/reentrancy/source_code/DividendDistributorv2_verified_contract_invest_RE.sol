/*
 * ===== SmartInject Injection Details =====
 * Function      : invest
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 1 findings
 * Total Found   : 3 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the investor's address before finalizing the lastDividend state update. The vulnerability requires:
 * 
 * 1. **Transaction 1**: Initial investment to establish non-zero investment state
 * 2. **Transaction 2+**: Subsequent investments trigger the external call, allowing reentrancy
 * 
 * **Multi-Transaction Exploitation Sequence:**
 * 1. **Setup Phase (Transaction 1)**: Attacker makes initial investment to establish `investors[attacker].investment > 0`
 * 2. **Exploitation Phase (Transaction 2)**: Attacker makes second investment, triggering the external call
 * 3. **Reentrancy Attack**: During the external call, attacker's contract re-enters `invest()` function
 * 4. **State Manipulation**: The reentrant call sees updated `investment` and `sumInvested` but stale `lastDividend` state
 * 5. **Dividend Exploitation**: Attacker can manipulate dividend calculations across multiple reentrant calls before `lastDividend` is properly updated
 * 
 * **Why Multi-Transaction is Required:**
 * - The external call only triggers when `investors[msg.sender].investment > 0` (requires prior investment)
 * - The vulnerability exploits the gap between investment state updates and dividend state finalization
 * - Each reentrant call can compound the attack by further manipulating the investment/dividend state ratio
 * - The attack becomes more profitable with accumulated state from previous transactions
 * 
 * **Realistic Attack Vector:**
 * An attacker deploys a contract with an `investmentNotification()` function that re-enters the `invest()` function, allowing them to manipulate their investment balance and dividend calculations across multiple transactions while the `lastDividend` state remains inconsistent.
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
            // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
            
            // Notify investor of successful investment - THIS CREATES REENTRANCY VULNERABILITY
            if (investors[msg.sender].investment > 0) {
                msg.sender.call(bytes4(keccak256("investmentNotification(uint256)")), investors[msg.sender].investment);
            }
            
            // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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