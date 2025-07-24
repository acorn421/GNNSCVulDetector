/*
 * ===== SmartInject Injection Details =====
 * Function      : withdraw
 * Vulnerability : Reentrancy
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 3 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding a pending withdrawals tracking system. The vulnerability requires multiple transactions to exploit:
 * 
 * 1. **State Accumulation**: Added `pendingWithdrawals` mapping and `totalPendingWithdrawals` counter that persist across transactions
 * 2. **Multi-Transaction Exploitation Path**: 
 *    - Transaction 1: Owner calls withdraw(), pendingWithdrawals[owner] is incremented, external call triggers reentrancy
 *    - During reentrancy: The state shows pending withdrawal amount, allowing recursive calls to add more to pending
 *    - Transaction 2+: Additional calls can exploit the accumulated pending state before cleanup occurs
 * 3. **Reentrancy Vulnerability**: External call `owner.send(availableBalance)` occurs before state cleanup, allowing reentrant calls to manipulate the pending withdrawal state
 * 4. **Realistic Business Logic**: The pending withdrawals system mimics real-world withdrawal queue patterns found in financial contracts
 * 
 * The vulnerability is multi-transaction because:
 * - Each failed/reentrant call accumulates state in pendingWithdrawals
 * - The vulnerability depends on the accumulated state from previous transactions
 * - Single transaction exploitation is prevented by the availableBalance calculation
 * - Multiple transactions are needed to build up exploitable pending withdrawal amounts
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

    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
mapping(address => uint) public pendingWithdrawals;
    uint public totalPendingWithdrawals;
    
    function withdraw() public {
        if (msg.sender == owner) {
            uint contractBalance = address(this).balance;
            uint availableBalance = contractBalance - totalPendingWithdrawals;
            
            if (availableBalance > 0) {
                // Add to pending withdrawals first
                pendingWithdrawals[owner] += availableBalance;
                totalPendingWithdrawals += availableBalance;
                
                // External call before state cleanup - VULNERABILITY
                if (owner.send(availableBalance)) {
                    // State cleanup only happens after successful send
                    pendingWithdrawals[owner] = 0;
                    totalPendingWithdrawals -= availableBalance;
                }
            }
        }
// ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
    }

    function kill() public {
        if (msg.sender == owner) selfdestruct(owner);
    }
}