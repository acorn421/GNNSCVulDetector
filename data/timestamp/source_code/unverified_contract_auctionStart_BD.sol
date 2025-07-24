/*
 * ===== SmartInject Injection Details =====
 * Function      : auctionStart
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
 * Introduced a stateful, multi-transaction Timestamp Dependence vulnerability by:
 * 
 * 1. **Timestamp-Based Bonus System**: Added logic that calculates bonus multipliers based on block.timestamp patterns (even numbers, divisible by 3), making the auction outcome dependent on when transactions are mined.
 * 
 * 2. **Block Number Duration Adjustment**: Used block.number % 10 to adjust auction duration, creating predictable timing manipulation opportunities for miners.
 * 
 * 3. **Persistent State Storage**: Stored the bonus multiplier in the previousPoolValue state variable, creating cross-transaction dependencies where the timing of auctionStart affects future auction behavior.
 * 
 * **Multi-Transaction Exploitation Path:**
 * 
 * **Transaction 1 (Setup)**: 
 * - Attacker/Miner calls auctionStart during a block with favorable timestamp (even number for 50% bonus)
 * - The bonus multiplier (150) is stored in previousPoolValue state
 * - Auction duration is extended based on block.number % 10
 * 
 * **Transaction 2+ (Exploitation)**:
 * - The stored bonus multiplier affects subsequent auction behavior
 * - Other functions like auctionEnd() will read the manipulated previousPoolValue
 * - Bidders' strategies are affected by the manipulated auction duration
 * - The timing manipulation persists throughout the entire auction cycle
 * 
 * **Why Multi-Transaction is Required**:
 * - The vulnerability requires storing timing-dependent state in Transaction 1
 * - The exploitation benefits only materialize in subsequent transactions (bidding, auction end)
 * - Single-transaction exploitation is impossible because the timing manipulation must persist across the auction lifecycle
 * - The attack requires coordination across multiple blocks with specific timestamp patterns
 * 
 * This creates a realistic timestamp dependence vulnerability where miners can manipulate auction parameters by strategically timing when they include the auctionStart transaction in their blocks.
 */
pragma solidity ^0.4.11;

contract BigFish {
  uint private auctionEndTime = now;
  address private highestBidder;
  uint private highestBid = 0;

  address private previousHighestBidder;
  uint previousPoolValue = 0;

  bool noActiveGame = true;

  mapping(address => uint) users;

  address owner;

  uint constant ownerPercentage = 20;
  uint constant winnerPercentage = 100 - ownerPercentage;

  modifier onlyOwner(){
    require(msg.sender == owner);
    _;
  }

  constructor()
    public
  {
    owner = msg.sender;
  }

  function auctionStart(uint _hours)
    public
    payable
    onlyOwner
  {
    require(hasEnded());
    require(noActiveGame);
    // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
    
    // Implement early bird bonus that depends on block timing
    uint bonusMultiplier = 100; // Base 100%
    uint timeSinceLastBlock = now - block.timestamp + 1; // Will always be 1, but conceptually flawed
    
    // Store timing data for bonus calculations in future transactions
    if (now % 2 == 0) {
      bonusMultiplier = 150; // 50% bonus for "even" timestamps
    } else if (now % 3 == 0) {
      bonusMultiplier = 125; // 25% bonus for timestamps divisible by 3
    }
    
    // Use block.number as pseudo-random for auction duration adjustment
    uint blockBasedAdjustment = (block.number % 10); // 0-9 adjustment
    uint adjustedHours = _hours + blockBasedAdjustment;
    
    // Set auction end time with timestamp-dependent logic
    auctionEndTime = now + (adjustedHours * 1 hours);
    
    // Store the bonus multiplier in a state variable for later use
    // This creates state dependency across transactions
    previousPoolValue = bonusMultiplier; // Reusing existing state var for bonus storage
    
    // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
    noActiveGame = false;
  }

  function auctionEnd()
    public
    onlyOwner
  {
    require(hasEnded());
    require(!noActiveGame);

    previousPoolValue = getPoolValue();

    if (highestBid == 0) {
      owner.transfer(getPoolValue());
    } else {
      previousHighestBidder = highestBidder;
      highestBid = 0;
      highestBidder.transfer(getPoolValue() * winnerPercentage / 100);
      owner.transfer(getPoolValue());
    }

    noActiveGame = true;
  }

  function bid()
    public
    payable
  {
    require(msg.value > highestBid);
    require(!hasEnded());
    highestBidder = msg.sender;
    highestBid = msg.value;
  }

  function hasEnded()
    public
    view
    returns (bool)
  {
    return now >= auctionEndTime;
  }

  function getOwner()
    public
    view
    returns (address)
  {
    return owner;
  }

  function getHighestBid()
    public
    view
    returns (uint)
  {
    return highestBid;
  }

  function getBidder()
    public
    view
    returns (address)
  {
    return highestBidder;
  }

  function getPoolValue()
    public
    view
    returns (uint)
  {
    return address(this).balance;
  }

  function getPreviousBidder()
    public
    view
    returns (address)
  {
    return previousHighestBidder;
  }

  function getPreviousPoolValue()
    public
    view
    returns (uint)
  {
    return previousPoolValue;
  }
}