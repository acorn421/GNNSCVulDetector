/*
 * ===== SmartInject Injection Details =====
 * Function      : initiateRefund
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 1 findings
 * Total Found   : 3 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-eth (SWC-107)
 *
 * === Description ===
 * This creates a multi-transaction reentrancy vulnerability where users must first call initiateRefund() to set up the refund state, then call processRefund() to execute it. The vulnerability exists because processRefund() makes an external call before updating the state variables, allowing for reentrancy attacks. The stateful nature requires the attacker to first initiate the refund, then exploit the processRefund function through recursive calls while the pendingRefunds state persists.
 */
pragma solidity ^0.4.17;

/*

Signals Society Membership Contract
-----------------------------------

*/

/**
 * Ownership functionality
 */
contract Ownable {
  address public owner;
  address public bot;
  // constructor, sets original owner address
  function Ownable() public {
    owner = msg.sender;
  }
  // modifier to restruct function use to the owner
  modifier onlyOwner() {
    require(msg.sender == owner);
    _;
  }    
  // modifier to restruct function use to the bot
  modifier onlyBot() {
    require(msg.sender == bot);
    _;
  }
  // lets owner change his address
  function changeOwner(address addr) public onlyOwner {
      owner = addr;
  }
  // lets owner change the bot's address    
  function changeBot(address addr) public onlyOwner {
      bot = addr;
  }
  // allows destruction of contract only if balance is empty
  function kill() public onlyOwner {
        require(this.balance == 0);
        selfdestruct(owner);
    }
}

/**
 * Manages membership prices
 */
contract Memberships is Ownable {
  // enumerates memberships (0, 1, 2)
  enum Membership { Day, Month, Lifetime }
  // holds the prices for the memberships
  mapping (uint => uint) internal prices;
  // returns the price for a single membership
  function getMembershipPrice(Membership membership) public view returns(uint) {
    return prices[uint(membership)];
  }
  // lets the owner set the price for a single membership
  function setMembershipPrice(Membership membership, uint amount) public onlyOwner {    
        require(amount > 0);
    prices[uint(membership)] = amount;
  }
}

/**
 * SignalsSociety Contract
 */
contract SignalsSociety is Ownable, Memberships {
  // lets the bot know a deposit was made
  event Deposited(address account, uint amount, uint balance, uint timestamp);
  // lets the bot know a membership was paid
  event MembershipPaid(address account, Membership membership, uint timestamp);

  // store the amount of ETH deposited by each account.
  mapping (address => uint) public balances;

  // --- Fixed: Move these mapping declarations outside of function ---
  mapping (address => uint) public pendingRefunds;
  mapping (address => bool) public refundRequested;

  // allows user to withdraw his balance
  function withdraw() public {
    uint amount = balances[msg.sender];
    // zero the pending refund before sending to prevent re-entrancy attacks
    balances[msg.sender] = 0;
    msg.sender.transfer(amount);

    // === FALLBACK INJECTION: Reentrancy ===
    // This function was added as a fallback when existing functions failed injection
    // Step 1: Initiate refund request with pending state
    // Step 2: Process the refund (vulnerable to reentrancy due to stateful nature)
    // === END FALLBACK INJECTION ===
  }

  function initiateRefund(uint amount) public {
    require(balances[msg.sender] >= amount);
    require(!refundRequested[msg.sender]);
    // Mark refund as requested but don't update balance yet
    refundRequested[msg.sender] = true;
    pendingRefunds[msg.sender] = amount;
  }

  function processRefund() public {
    require(refundRequested[msg.sender]);
    require(pendingRefunds[msg.sender] > 0);
    uint amount = pendingRefunds[msg.sender];
    // External call before state update - reentrancy vulnerability
    msg.sender.call.value(amount)();
    // State updates after external call (vulnerable)
    balances[msg.sender] -= amount;
    pendingRefunds[msg.sender] = 0;
    refundRequested[msg.sender] = false;
  }

  // deposits ETH to a user's account
  function deposit(address account, uint amount) public {
    // deposit the amount to the user's account
    balances[account] += amount;
    // let the bot know something was deposited
    Deposited(account, amount, balances[account], now);
  }
  // accepts the membership payment by moving eth from the user's account
  // to the owner's account
  function acceptMembership(address account, Membership membership, uint discount) public onlyBot {
    // get the price for the membership they selected minus any discounts for special promotions
    var price = getMembershipPrice(membership) - discount;
    // make sure they have enough balance to pay for it
    require(balances[account] >= price);
    // transfer the price to the contract owner account
    balances[account] -= price;
    balances[owner] += price;
    // let the bot know the membershipt was paid
    MembershipPaid(account, membership, now);
  }
  // default function.  Called when a user sends ETH to the contract.
  // deposits the eth to their bank account
  function () public payable {
    deposit(msg.sender, msg.value);
  }
}
