/*
 * ===== SmartInject Injection Details =====
 * Function      : placeBid
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 2 findings
 * Total Found   : 6 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-eth (SWC-107)
 * 2. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by:
 * 
 * 1. **Replaced safe refund mechanism**: Changed from the private `refundBid()` function (which used `.send()` with gas limits) to a direct `.call.value()` without gas restrictions, creating a full reentrancy window.
 * 
 * 2. **Preserved state access during reentrancy**: The vulnerable external call occurs before `highestBid` is updated, allowing reentrant calls to see and manipulate the old auction state.
 * 
 * 3. **Multi-transaction exploitation pattern**: 
 *    - **Transaction 1**: Attacker deploys a malicious contract and places initial bid
 *    - **Transaction 2**: Victim places higher bid, triggering refund to attacker's contract
 *    - **During refund callback**: Attacker's contract can re-enter `placeBid()` multiple times, seeing the old `highestBid` state and potentially manipulating auction mechanics
 *    - **Subsequent transactions**: The vulnerability compounds as each bid creates new opportunities for reentrancy exploitation
 * 
 * 4. **Stateful vulnerability characteristics**:
 *    - The vulnerability depends on accumulated auction state (`highestBid`) persisting between transactions
 *    - Each successful bid creates new attack vectors for future transactions
 *    - The exploit requires building up auction state through multiple legitimate bidding rounds
 *    - Attackers must first establish themselves as the highest bidder in one transaction before exploiting the reentrancy in subsequent transactions
 * 
 * 5. **Realistic code changes**: The modification appears as a "performance optimization" (removing gas limits) that could realistically be introduced during development, making it a subtle but dangerous vulnerability.
 */
pragma solidity ^0.4.18;

contract DomainAuction {
    address public owner;

    struct Bid {
        uint timestamp;
        address bidder;
        uint amount;
        string url;
    }

    struct WinningBid {
        uint winTimestamp;
        uint bidTimestamp;
        address bidder;
        uint bidAmount;
        string url;
    }

    Bid public highestBid;

    WinningBid public winningBid;

    event BidLog(uint timestamp, address bidder, uint amount, string url);
    event WinningBidLog(uint winTimestamp, uint bidTimestamp, address bidder, uint amount, string url);
    event Refund(uint timestamp, address bidder, uint amount);

    ///////////////////////////////////

    function placeBid(string url) public payable {
        require(msg.value >= ((highestBid.amount * 11) / 10));
        Bid memory newBid = Bid(now, msg.sender, msg.value, url);

        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // Store the current highest bid before refunding
        Bid memory currentHighest = highestBid;
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        // Refund the current highest bid.
        // Do not refund anything on the first `placeBid` call.
        if (highestBid.bidder != 0) {
            // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
            // Direct call to bidder with gas stipend removal - creates reentrancy window
            bool success = highestBid.bidder.call.value(highestBid.amount)("");
            if (success) {
                emit Refund(now, currentHighest.bidder, currentHighest.amount);
            }
            // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        }

        // Update the highest bid and log the event
        highestBid = newBid;
        emit BidLog(newBid.timestamp, newBid.bidder, newBid.amount, newBid.url);
    }

    // This might fail if the bidder is trying some contract bullshit, but they do this
    // at their own risk. It won't fail if the bidder is a non-contract address.
    // It is very important to use `send` instead of `transfer`. Otherwise this could fail
    // and this contract could get hijacked.
    // See https://ethereum.stackexchange.com/questions/19341/address-send-vs-address-transfer-best-practice-usage
    function refundBid(Bid bid) private {
        bid.bidder.send(bid.amount);
        emit Refund(now, bid.bidder, bid.amount);
    }

    // This will need to be triggered externally every x days
    function pickWinner() public payable {
        require(msg.sender == owner);

        if (winningBid.bidTimestamp != highestBid.timestamp) {
          // Have to store the new winning bid in memory in order to emit it as part
          // of an event. Can't emit an event straight from a stored variable.
          WinningBid memory newWinningBid = WinningBid(now, highestBid.timestamp, highestBid.bidder, highestBid.amount, highestBid.url);
          winningBid = newWinningBid;
          emit WinningBidLog(
              newWinningBid.winTimestamp,
              newWinningBid.bidTimestamp,
              newWinningBid.bidder,
              newWinningBid.bidAmount,
              newWinningBid.url
          );
        }
    }

    ///////////////////////////////////

    constructor() public payable {
        owner = msg.sender;
    }

    function withdraw() public {
        if (msg.sender == owner) owner.send(address(this).balance);
    }

    function kill() public {
        if (msg.sender == owner) selfdestruct(owner);
    }
}