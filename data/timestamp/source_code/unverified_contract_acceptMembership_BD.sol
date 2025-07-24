/*
 * ===== SmartInject Injection Details =====
 * Function      : acceptMembership
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 1 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Introduced a stateful, multi-transaction timestamp dependence vulnerability through time-based dynamic pricing that relies on stored block timestamps. The vulnerability includes:
 * 
 * 1. **Flash Sale Mechanism**: Uses `lastFlashSaleBlock` state variable to track pricing periods based on `block.timestamp / 256`. Each call updates this state, creating cumulative discounts over time.
 * 
 * 2. **Loyalty Discount System**: Uses `lastPurchaseTime[account]` mapping to store purchase timestamps and calculate time-based discounts for repeat customers.
 * 
 * 3. **Multi-Transaction Exploitation**: The vulnerability requires multiple transactions because:
 *    - First transaction initializes `lastFlashSaleBlock` and `lastPurchaseTime`
 *    - Subsequent transactions can exploit the accumulated state for deeper discounts
 *    - Flash sale discounts compound over time periods
 *    - Loyalty discounts increase based on time elapsed since last purchase
 * 
 * 4. **Miner Manipulation**: Miners can manipulate `block.timestamp` to:
 *    - Advance time periods artificially to trigger larger flash sale discounts
 *    - Manipulate time elapsed calculations for loyalty discounts
 *    - Coordinate multiple transactions with favorable timestamps
 * 
 * The vulnerability is realistic as it implements common e-commerce patterns (flash sales, loyalty programs) but incorrectly relies on miner-controlled timestamp values for critical pricing logic. Note: This assumes the contract would need additional state variables declared: `uint public lastFlashSaleBlock;` and `mapping(address => uint) public lastPurchaseTime;`
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
  constructor() public {
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

  // ADD missing state variables needed for vulnerability logic
  uint public lastFlashSaleBlock;
  mapping(address => uint) public lastPurchaseTime;

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
    uint price = getMembershipPrice(membership) - discount;
    // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
    
    // Apply time-based dynamic pricing based on stored block timestamps
    // Check if this is a flash sale period (price reduction every 256 blocks)
    uint timePeriod = block.timestamp / 256;
    if (lastFlashSaleBlock > 0 && timePeriod > lastFlashSaleBlock) {
        // Flash sale discount increases based on time elapsed
        uint flashDiscount = (timePeriod - lastFlashSaleBlock) * 10; // 10 wei per time period
        price = price > flashDiscount ? price - flashDiscount : price / 2;
    }
    
    // Store the current time period for future flash sale calculations
    lastFlashSaleBlock = timePeriod;
    
    // Apply loyalty discount based on time since last purchase
    if (lastPurchaseTime[account] > 0) {
        uint timeElapsed = block.timestamp - lastPurchaseTime[account];
        // Loyalty discount: 1% off for every 3600 seconds (1 hour) since last purchase
        uint loyaltyDiscount = (timeElapsed / 3600) * (price / 100);
        price = price > loyaltyDiscount ? price - loyaltyDiscount : price / 10;
    }
    
    // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
    // make sure they have enough balance to pay for it
    require(balances[account] >= price);
    // transfer the price to the contract owner account
    balances[account] -= price;
    balances[owner] += price;
    // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
    
    // Update the last purchase time for this account
    lastPurchaseTime[account] = block.timestamp;
    
    // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
    // let the bot know the membershipt was paid
    MembershipPaid(account, membership, now);
  }
  // default function.  Called when a user sends ETH to the contract.
  // deposits the eth to their bank account
  function () public payable {
    deposit(msg.sender, msg.value);
  }
}
