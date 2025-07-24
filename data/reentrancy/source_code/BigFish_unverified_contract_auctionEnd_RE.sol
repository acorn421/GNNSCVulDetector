/*
 * ===== SmartInject Injection Details =====
 * Function      : auctionEnd
 * Vulnerability : Reentrancy
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
 * The vulnerability is introduced by reordering the operations in the else block. The key changes are:
 * 
 * 1. **External Call Before State Update**: The highestBidder.transfer() call now occurs BEFORE highestBid is set to 0 and before noActiveGame is set to true.
 * 
 * 2. **State Fragmentation**: The state updates are now split across the external call, creating a window where the contract is in an inconsistent state.
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 
 * **Transaction 1**: Owner calls auctionEnd()
 * - Function enters the else block (highestBid > 0)
 * - Sets previousHighestBidder = highestBidder
 * - Calls highestBidder.transfer() - this is where reentrancy occurs
 * - If highestBidder is a malicious contract, it can:
 *   - Re-enter and call bid() with the same highestBid value (since highestBid hasn't been reset yet)
 *   - Or trigger other state-dependent functions before noActiveGame is set
 * 
 * **Transaction 2**: Malicious contract's fallback/receive function
 * - During the transfer, the malicious contract can make additional calls
 * - Since highestBid is still non-zero and noActiveGame is still false, the contract state appears as if the auction is still active
 * - The attacker can potentially manipulate bidding or trigger other functions that depend on the auction state
 * 
 * **Transaction 3**: Original auctionEnd() continues
 * - After the reentrancy, the original function continues
 * - Sets highestBid = 0 (too late)
 * - Makes second transfer to owner
 * - Sets noActiveGame = true (too late)
 * 
 * **Why Multi-Transaction is Required:**
 * - The vulnerability requires the malicious contract to have a fallback/receive function that executes during the transfer
 * - The exploitation happens across the boundary of the external call, creating a stateful vulnerability
 * - The attacker needs to deploy a malicious contract as the highest bidder first (Transaction 1), then exploit during the transfer (Transaction 2), making it inherently multi-transaction
 * - The inconsistent state persists across transaction boundaries, allowing for complex exploitation patterns that cannot be achieved in a single atomic transaction
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
      // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
      noActiveGame = true;
      // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
    } else {
      previousHighestBidder = highestBidder;
      // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
      // External call before state update - allows reentrancy
      highestBidder.transfer(getPoolValue() * winnerPercentage / 100);
      
      // State updates occur after external call
      // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
      highestBid = 0;
      owner.transfer(getPoolValue());
      // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
      noActiveGame = true;
      // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
    }
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