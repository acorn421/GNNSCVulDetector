/*
 * ===== SmartInject Injection Details =====
 * Function      : pickWinner
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
 * **STATEFUL, MULTI-TRANSACTION REENTRANCY VULNERABILITY**
 * 
 * **Specific Changes Made:**
 * 1. **Added Winner Reward Logic**: Introduced a 10% reward calculation based on the highest bid amount
 * 2. **External Call Before State Update**: Added `highestBid.bidder.call.value(rewardAmount)("")` before updating the `winningBid` state
 * 3. **State Update After External Call**: The critical `winningBid = newWinningBid` assignment now occurs after the external call, creating a reentrancy window
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 
 * **Prerequisites (Transaction 1-N):**
 * - Attacker must first participate in legitimate auction bidding to become the `highestBid.bidder`
 * - Multiple `placeBid()` calls accumulate funds in the contract
 * - Contract must build up sufficient balance for rewards
 * 
 * **Exploitation (Transaction N+1):**
 * 1. Owner calls `pickWinner()` with attacker as `highestBid.bidder`
 * 2. Function calculates reward and calls attacker's contract
 * 3. Attacker's fallback function re-enters `pickWinner()`
 * 4. Since `winningBid.bidTimestamp` hasn't been updated yet, the condition passes again
 * 5. Attacker receives multiple rewards before state is finally updated
 * 
 * **Why Multi-Transaction is Required:**
 * - **State Accumulation**: Contract must accumulate funds through multiple `placeBid()` calls
 * - **Bidding Sequence**: Attacker must establish themselves as highest bidder through legitimate bidding
 * - **Owner Interaction**: Requires owner to trigger `pickWinner()` - cannot be self-initiated
 * - **Balance Dependency**: Exploitation effectiveness depends on accumulated contract balance from previous auction rounds
 * 
 * **Critical Vulnerability Details:**
 * - The `winningBid` state update happens AFTER the external call
 * - During reentrancy, `winningBid.bidTimestamp != highestBid.timestamp` remains true
 * - Each reentrant call can drain additional funds before the state is finally updated
 * - The vulnerability is only exploitable when there are accumulated funds and a legitimate auction winner exists
 * 
 * This creates a realistic, stateful vulnerability that requires careful setup across multiple transactions and cannot be exploited atomically.
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
          // Have to store the new winning bid in memory in order to emit it as part
          // of an event. Can't emit an event straight from a stored variable.
          WinningBid memory newWinningBid = WinningBid(now, highestBid.timestamp, highestBid.bidder, highestBid.amount, highestBid.url);
          // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
          
          // Calculate winner reward (10% of the highest bid)
          uint rewardAmount = highestBid.amount / 10;
          
          // Notify winner and transfer reward before updating state
          if (rewardAmount > 0 && address(this).balance >= rewardAmount) {
              // External call to winner - potential reentrancy point
              bool success = highestBid.bidder.call.value(rewardAmount)("");
              require(success, "Winner reward transfer failed");
          }
          
          // Update state after external call - vulnerable to reentrancy
          // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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