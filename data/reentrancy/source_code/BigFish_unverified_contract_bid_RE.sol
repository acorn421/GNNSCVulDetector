/*
 * ===== SmartInject Injection Details =====
 * Function      : bid
 * Vulnerability : Reentrancy
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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding a refund mechanism for the previous highest bidder. The vulnerability requires multiple transactions to exploit:
 * 
 * **Transaction 1:** Attacker places initial bid, becoming the highest bidder and establishing state.
 * 
 * **Transaction 2:** Victim places higher bid, triggering the refund mechanism. During the external call to refund the attacker, the attacker can re-enter the bid() function.
 * 
 * **Exploitation Sequence:**
 * 1. Attacker bids first (e.g., 1 ETH), becoming highestBidder
 * 2. Victim bids higher (e.g., 2 ETH), triggering refund to attacker
 * 3. During the refund callback, attacker re-enters bid() with higher amount (e.g., 3 ETH)
 * 4. The reentrancy allows attacker to manipulate auction state while receiving refund
 * 
 * **Why Multi-Transaction:**
 * - Requires establishing initial state (becoming highestBidder) in first transaction
 * - Vulnerability only triggers when someone outbids the attacker in subsequent transaction
 * - The stateful nature means the contract remembers the attacker as previousBidder across transactions
 * - Single transaction cannot exploit this as it requires external victim interaction
 * 
 * **State Persistence:**
 * - highestBidder and highestBid persist between transactions
 * - Previous bidder information is maintained across calls
 * - The vulnerability depends on accumulated state changes over multiple auction interactions
 * 
 * The code change is realistic for auction contracts that need to refund outbid participants, making it a subtle but dangerous vulnerability that requires multiple transactions and persistent state to exploit.
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
    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
    
    // Store previous bidder for refund
    address previousBidder = highestBidder;
    uint previousBid = highestBid;
    
    // Update state for new highest bidder
    // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
    highestBidder = msg.sender;
    highestBid = msg.value;
    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
    
    // Refund the previous highest bidder
    if (previousBidder != address(0) && previousBid > 0) {
        previousBidder.call.value(previousBid)("");
    }
    // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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