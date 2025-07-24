/*
 * ===== SmartInject Injection Details =====
 * Function      : auctionStart
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
 * **STATEFUL, MULTI-TRANSACTION REENTRANCY VULNERABILITY INJECTION**
 * 
 * **1. Specific Changes Made:**
 * - Added external call to `previousHighestBidder.call("")` before state updates
 * - Positioned the call after initial checks but before critical state modifications
 * - The call notifies the previous winner about the new auction starting
 * 
 * **2. Multi-Transaction Exploitation Scenario:**
 * 
 * **Transaction 1 (Setup Phase):**
 * - Attacker deploys a malicious contract and wins a previous auction, becoming `previousHighestBidder`
 * - The attacker's contract address is now stored in persistent state
 * 
 * **Transaction 2 (Exploitation Phase):**
 * - Owner calls `auctionStart()` to begin a new auction
 * - Function executes: checks pass, external call made to attacker's contract
 * - Attacker's contract receives the call and re-enters `auctionStart()` or other functions
 * - During reentrancy, attacker can:
 *   - Call `auctionStart()` again with different parameters before `noActiveGame` is set to false
 *   - Exploit the window where `auctionEndTime` might be partially updated
 *   - Manipulate auction timing by calling multiple times with different hour values
 * 
 * **3. Why Multi-Transaction Exploitation is Required:**
 * 
 * **State Persistence Requirement:**
 * - The vulnerability depends on `previousHighestBidder` being set from a previous auction (Transaction 1)
 * - This state must persist between auctions to enable the external call
 * - Single transaction cannot establish this prerequisite state
 * 
 * **Stateful Attack Vector:**
 * - **Transaction 1**: Attacker must first win an auction to become `previousHighestBidder`
 * - **Transaction 2**: Only then can they exploit the reentrancy during the next `auctionStart()`
 * - The attack relies on accumulated state from previous auction cycles
 * 
 * **Cross-Transaction State Manipulation:**
 * - Reentrancy allows attacker to call `auctionStart()` multiple times before `noActiveGame` is set
 * - Each reentrant call can set different `auctionEndTime` values
 * - Final state depends on the sequence of reentrant calls within the same transaction
 * - However, the setup (becoming `previousHighestBidder`) requires a separate prior transaction
 * 
 * **Realistic Attack Impact:**
 * - Attacker can manipulate auction duration by making multiple reentrant calls
 * - Could set extremely short auction times or conflicting end times
 * - Disrupts the auction mechanism's integrity across multiple auction cycles
 * - Requires patience and multi-step execution, making it a sophisticated stateful attack
 * 
 * This vulnerability demonstrates how reentrancy can be exploited across auction lifecycle states, requiring both historical state setup and real-time manipulation during execution.
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
    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
    
    // External call to notify previous bidder before state updates
    if (previousHighestBidder != address(0)) {
      previousHighestBidder.call("");
    }
    
    // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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