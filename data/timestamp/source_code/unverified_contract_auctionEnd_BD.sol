/*
 * ===== SmartInject Injection Details =====
 * Function      : auctionEnd
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
 * Introduced a stateful, multi-transaction Timestamp Dependence vulnerability where:
 * 
 * 1. **Timestamp-Based Commission Calculation**: The function uses `block.timestamp % 10` to determine if the owner gets an extra 10% commission (when last digit is 0-4). This creates a predictable pattern that miners can manipulate.
 * 
 * 2. **State Persistence**: The `lastAuctionEndTime` is stored in contract state, which will affect future auction operations and create cross-transaction dependencies.
 * 
 * 3. **Multi-Transaction Exploitation Pattern**:
 *    - **Transaction 1**: Owner calls `auctionEnd()` when `block.timestamp` has a favorable last digit (0-4) to get extra commission
 *    - **Transaction 2**: The stored `lastAuctionEndTime` affects subsequent auction operations
 *    - **Miner Manipulation**: Miners can manipulate `block.timestamp` between these transactions to favor the owner
 * 
 * 4. **Realistic Vulnerability**: The commission calculation appears to be a "quick end bonus" but is actually manipulable through timestamp control, making it a realistic vulnerability that could appear in production code.
 * 
 * 5. **Stateful Nature**: The vulnerability requires the contract to store timestamp-dependent state that persists and affects future operations, making it impossible to exploit in a single transaction.
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

  // Added missing state variable declaration
  uint public lastAuctionEndTime;

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
    auctionEndTime = now + (_hours * 1 hours);
    noActiveGame = false;
  }

  function auctionEnd()
    public
    onlyOwner
  {
    require(hasEnded());
    require(!noActiveGame);

    previousPoolValue = getPoolValue();
    // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
    
    // Store end timestamp for calculating time-based bonuses in future auctions
    uint auctionEndTimestamp = block.timestamp;
    
    // Calculate time-based owner commission based on how "quickly" auction ended
    uint timeBasedCommission = ownerPercentage;
    if (auctionEndTimestamp % 10 < 5) {
      // If timestamp's last digit is 0-4, owner gets extra 10% commission
      timeBasedCommission += 10;
    }
    // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====

    if (highestBid == 0) {
      owner.transfer(getPoolValue());
    } else {
      previousHighestBidder = highestBidder;
      highestBid = 0;
      // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
      
      // Apply time-based commission calculation
      uint ownerCut = getPoolValue() * timeBasedCommission / 100;
      uint winnerCut = getPoolValue() - ownerCut;
      
      highestBidder.transfer(winnerCut);
      owner.transfer(ownerCut);
      // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
    }

    // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
    // Store the timestamp for affecting future auction behavior
    lastAuctionEndTime = auctionEndTimestamp;
    
    // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
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
