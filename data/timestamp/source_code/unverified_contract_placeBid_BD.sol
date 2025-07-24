/*
 * ===== SmartInject Injection Details =====
 * Function      : placeBid
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 4 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Introduced a timestamp-dependent anti-spam protection mechanism that requires a 30-second gap between bids. This creates a stateful, multi-transaction vulnerability where:
 * 
 * 1. **Stateful Component**: The highestBid.timestamp is stored in contract state and persists between transactions
 * 2. **Multi-Transaction Requirement**: The vulnerability requires multiple sequential transactions to exploit - an attacker must first place a bid to establish a timestamp, then exploit the timing window in subsequent transactions
 * 3. **Timestamp Dependence**: The vulnerability relies on block.timestamp (now) comparison, which miners can manipulate within ~15 second tolerance
 * 
 * **Multi-Transaction Exploitation Scenarios**:
 * 
 * **Scenario 1 - Miner Manipulation**:
 * - Transaction 1: Attacker places legitimate bid at timestamp T
 * - Transaction 2: Attacker (if they're a miner) can manipulate the next block's timestamp to be exactly T+30 to bypass the delay, while honest bidders still see T+29 and are rejected
 * - This allows miners to place consecutive bids without waiting the full 30 seconds
 * 
 * **Scenario 2 - Frontrunning with Timing**:
 * - Transaction 1: Honest user places bid at timestamp T
 * - Transaction 2: Attacker waits until just before T+30 and places a higher bid
 * - Transaction 3: Attacker can immediately place another bid by manipulating timestamp or exploiting clock drift between nodes
 * 
 * **Scenario 3 - Accumulated State Exploitation**:
 * - Multiple transactions build up a pattern where the attacker can predict when the next valid bid window opens
 * - The persistent state (highestBid.timestamp) creates a predictable timing pattern that can be exploited across multiple blocks
 * 
 * **Why Multi-Transaction is Required**:
 * - Cannot exploit in single transaction because you need an existing highestBid.timestamp to create the timing constraint
 * - The vulnerability emerges from the interaction between persistent state and timestamp validation across multiple function calls
 * - Each exploitation requires building upon the state established by previous transactions
 * 
 * This injection maintains the auction's intended functionality while creating a realistic timing-based vulnerability that exists in many real-world smart contracts attempting to implement rate limiting or anti-spam measures.
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
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        
        // Anti-spam protection: minimum 30 second gap between bids
        // This creates a time-based window that can be exploited
        require(now >= highestBid.timestamp + 30, "Must wait 30 seconds between bids");
        
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
        Bid memory newBid = Bid(now, msg.sender, msg.value, url);

        // Refund the current highest bid.
        // Do not refund anything on the first `placeBid` call.
        if (highestBid.bidder != 0) {
            refundBid(highestBid);
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