/*
 * ===== SmartInject Injection Details =====
 * Function      : setBidDeadlineExtension
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 2 issues
 * Retry Count   : 0
 *
 * === Description ===
 * This vulnerability introduces a stateful, multi-transaction timestamp dependence issue. The attack requires: 1) Owner first calls setBidDeadlineExtension() to enable the extension feature, 2) Multiple bidders call extendAuctionOnBid() near the auction end time, 3) A malicious miner can manipulate timestamps across these transactions to either extend or prevent extensions, affecting auction fairness. The vulnerability persists across transactions through the bidDeadlineExtension and lastBidTime state variables.
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

  // === FALLBACK INJECTION: Timestamp Dependence ===
  // This function was added as a fallback when existing functions failed injection
  uint private bidDeadlineExtension = 0;
  uint private lastBidTime = 0;

  modifier onlyOwner(){
    require(msg.sender == owner);
    _;
  }

  function setBidDeadlineExtension(uint _minutes)
    public
    onlyOwner
  {
    require(_minutes <= 60); // Max 1 hour extension
    bidDeadlineExtension = _minutes;
  }

  function extendAuctionOnBid()
    public
    payable
  {
    require(msg.value > highestBid);
    require(!hasEnded());
    require(bidDeadlineExtension > 0);

    // Vulnerable: Using block.timestamp for deadline extension
    // Can be manipulated by miners across multiple transactions
    if (now >= auctionEndTime - (bidDeadlineExtension * 1 minutes)) {
      auctionEndTime = now + (bidDeadlineExtension * 1 minutes);
    }

    lastBidTime = now;
    highestBidder = msg.sender;
    highestBid = msg.value;
  }

  function getLastBidTime()
    public
    view
    returns (uint)
  {
    return lastBidTime;
  }

  function getBidDeadlineExtension()
    public
    view
    returns (uint)
  {
    return bidDeadlineExtension;
  }
  // === END FALLBACK INJECTION ===

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
