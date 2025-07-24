/*
 * ===== SmartInject Injection Details =====
 * Function      : pickWinner
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
 * Introduced a stateful timestamp dependence vulnerability that requires multiple transactions to exploit. The vulnerability adds time-based bonus calculations that:
 * 
 * 1. **State Accumulation**: Uses previous winningBid.winTimestamp to determine bonus multipliers, creating state dependency across multiple pickWinner() calls
 * 2. **Timestamp Manipulation**: Miners can manipulate block.timestamp within ~15 seconds to influence bonus calculations
 * 3. **Multi-Transaction Exploitation**: Requires at least 2 transactions - first to set winningBid.winTimestamp, second to exploit the time-based bonus logic
 * 4. **Compound Effects**: The "quick successive wins" logic creates additional exploitation opportunities when multiple pickWinner() calls happen within 6 hours
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * - Transaction 1: Owner calls pickWinner() to establish initial winningBid.winTimestamp
 * - Transaction 2: Attacker (if they become owner through other means) or colluding miner times the next pickWinner() call to maximize time bonuses
 * - Transaction 3+: Subsequent calls can exploit the compound bonus logic by timing calls within 6-hour windows
 * 
 * **Why Multi-Transaction Required:**
 * - The vulnerability relies on comparing current timestamp with stored winningBid.winTimestamp from previous calls
 * - Single transaction cannot exploit the "quick successive wins" multiplier without prior state
 * - Time-based bonuses accumulate over multiple auction cycles, requiring persistent state changes
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
          // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
          // Time-based winner selection bonus - longer auction periods get higher payouts
          uint auctionDuration = now - highestBid.timestamp;
          uint timeBonus = 0;
          
          // Apply time-based bonus that accumulates over multiple winner selections
          if (auctionDuration >= 1 days) {
              timeBonus = (auctionDuration / 1 days) * (highestBid.amount / 100); // 1% per day
              // Store the bonus calculation timestamp for future reference
              if (winningBid.winTimestamp > 0) {
                  uint timeSinceLastWin = now - winningBid.winTimestamp;
                  // Compound bonus if multiple wins happen within short time frames
                  if (timeSinceLastWin < 6 hours) {
                      timeBonus = timeBonus * 2; // Double bonus for quick successive wins
                  }
              }
          }
          
          // Calculate final winning amount with time-dependent bonus
          uint finalAmount = highestBid.amount + timeBonus;
          
          // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
          // Have to store the new winning bid in memory in order to emit it as part
          // of an event. Can't emit an event straight from a stored variable.
          // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
          WinningBid memory newWinningBid = WinningBid(now, highestBid.timestamp, highestBid.bidder, finalAmount, highestBid.url);
          // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
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