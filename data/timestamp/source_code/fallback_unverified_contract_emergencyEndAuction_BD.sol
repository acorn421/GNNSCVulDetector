/*
 * ===== SmartInject Injection Details =====
 * Function      : emergencyEndAuction
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 5 issues
 * Retry Count   : 0
 *
 * === Description ===
 * This vulnerability introduces a stateful, multi-transaction timestamp dependence issue. The owner must first call emergencyEndAuction() to activate emergency mode and set an end time based on 'now'. Then in a separate transaction, finalizeEmergencyEnd() checks if 'now >= emergencyEndTime'. A malicious miner could manipulate the timestamp in the second transaction to either prevent or force the emergency finalization, potentially allowing them to place bids when the auction should be closed or preventing legitimate emergency endings.
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

    // === FALLBACK INJECTION: Timestamp Dependence ===
    // This function was added as a fallback when existing functions failed injection
    uint public emergencyEndTime;
    bool public emergencyModeActivated;

    // Emergency function to end auction early in case of critical issues
    function emergencyEndAuction() public {
        require(msg.sender == owner);
        require(!emergencyModeActivated);

        // Set emergency end time to current timestamp + 1 hour
        emergencyEndTime = now + 1 hours;
        emergencyModeActivated = true;
    }

    // Function to finalize emergency auction ending
    function finalizeEmergencyEnd() public {
        require(msg.sender == owner);
        require(emergencyModeActivated);
        require(now >= emergencyEndTime); // Vulnerable to timestamp manipulation

        // Automatically pick winner and end auction
        if (winningBid.bidTimestamp != highestBid.timestamp) {
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

        // Reset emergency state
        emergencyModeActivated = false;
        emergencyEndTime = 0;
    }
    // === END FALLBACK INJECTION ===

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
