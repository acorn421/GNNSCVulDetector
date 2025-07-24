/*
 * ===== SmartInject Injection Details =====
 * Function      : requestMembershipRefund
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 1 issues
 * Retry Count   : 0
 *
 * === Description ===
 * This vulnerability introduces a timestamp dependence issue where users can request membership refunds within a 24-hour window. The vulnerability is stateful and multi-transaction because: 1) A user must first call requestMembershipRefund() to initiate the refund request (first transaction), which stores the request timestamp in contract state, 2) Then call processMembershipRefund() within 24 hours to complete the refund (second transaction), 3) The vulnerability relies on the 'now' timestamp for time-based logic that can be manipulated by miners within reasonable bounds, potentially allowing users to extend refund windows or prevent legitimate refunds, 4) The state persists between transactions through the refundRequestTime mapping, making this a multi-transaction vulnerability.
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

  // === FALLBACK INJECTION: Timestamp Dependence ===
  // Mapping to track refund requests with timestamp
  mapping(address => uint) public refundRequestTime;
  mapping(address => Membership) public refundMembership;
  mapping(address => bool) public refundRequested;

  // Event for refund requests
  event RefundRequested(address account, Membership membership, uint timestamp);
  event RefundProcessed(address account, uint amount, uint timestamp);

  // Allows users to request a refund within 24 hours of membership purchase
  function requestMembershipRefund(Membership membership) public {
      require(!refundRequested[msg.sender], "Refund already requested");
      // Store the refund request with current timestamp
      refundRequestTime[msg.sender] = now;
      refundMembership[msg.sender] = membership;
      refundRequested[msg.sender] = true;
      RefundRequested(msg.sender, membership, now);
  }

  // Processes refund if requested within 24 hours (86400 seconds)
  function processMembershipRefund() public {
      require(refundRequested[msg.sender], "No refund request found");
      // VULNERABILITY: Using 'now' timestamp for time-based logic
      // Miners can manipulate block timestamps within reasonable bounds
      // The 24-hour window can be exploited by miners to either:
      // 1. Extend the window by setting future timestamps
      // 2. Prevent legitimate refunds by setting past timestamps
      uint timePassed = now - refundRequestTime[msg.sender];
      require(timePassed <= 86400, "Refund period expired"); // 24 hours
      // Get the membership price to refund
      uint refundAmount = getMembershipPrice(refundMembership[msg.sender]);
      // Add refund amount back to user's balance
      balances[msg.sender] += refundAmount;
      // Deduct from owner's balance
      if (balances[owner] >= refundAmount) {
          balances[owner] -= refundAmount;
      }
      // Clear refund request
      refundRequested[msg.sender] = false;
      refundRequestTime[msg.sender] = 0;
      RefundProcessed(msg.sender, refundAmount, now);
  }
  // === END FALLBACK INJECTION ===

  // allows user to withdraw his balance
  function withdraw() public {
    uint amount = balances[msg.sender];
    // zero the pending refund before sending to prevent re-entrancy attacks
    balances[msg.sender] = 0;
    msg.sender.transfer(amount);
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
