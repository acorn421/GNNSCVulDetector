/*
 * ===== SmartInject Injection Details =====
 * Function      : contribute
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 2 findings
 * Total Found   : 5 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-benign (SWC-107)
 * 2. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the contributor's address before state updates. The vulnerability requires multiple transactions to exploit:
 * 
 * **Specific Changes Made:**
 * 1. Added external call `msg.sender.call.value(0)(bytes4(keccak256("onContributionReceived(uint256)")), msg.value)` before state updates
 * 2. Wrapped state updates in conditional blocks based on callback success
 * 3. Placed the external call before the critical state modifications (`contributions[msg.sender] += msg.value` and `totalContributions += msg.value`)
 * 
 * **Multi-Transaction Exploitation Pattern:**
 * 1. **Transaction 1 (Setup)**: Attacker deploys a malicious contract and makes initial contribution to establish baseline state
 * 2. **Transaction 2+ (Exploitation)**: Attacker's contract implements `onContributionReceived` fallback that:
 *    - Re-enters the `contribute()` function before original state is updated
 *    - Exploits the fact that `contributions[msg.sender]` hasn't been updated yet
 *    - Accumulates multiple contributions while the state tracking lags behind
 *    - Requires multiple calls to build up significant exploitable state differences
 * 
 * **Why Multi-Transaction is Required:**
 * - The vulnerability depends on accumulated state across multiple contribution calls
 * - Each reentrant call adds to the state inconsistency that builds up over time
 * - The exploit requires establishing a baseline contribution state first, then exploiting the reentrancy gap
 * - Maximum impact is achieved through repeated exploitation across multiple transactions
 * - Single transaction exploitation is limited by gas constraints and the need to establish the attack pattern
 * 
 * **Exploitation Mechanics:**
 * - Attacker's contract receives callback before their contribution is recorded
 * - During callback, attacker can call `contribute()` again with the same or different amounts
 * - State updates happen after external calls, creating windows for manipulation
 * - Multiple rounds of this pattern amplify the state inconsistency
 * - The vulnerability becomes more severe with accumulated state differences over time
 */
pragma solidity ^0.4.4;

contract DutchAuctionInterface {
    function bid(address receiver) payable returns (uint);
    function claimTokens(address receiver);
    function stage() returns (uint);
    TokenInterface public gnosisToken;
}


contract TokenInterface {
    function transfer(address to, uint256 value) returns (bool success);
    function balanceOf(address owner) constant returns (uint256 balance);
}


contract ProxySender {

    event BidSubmission(address indexed sender, uint256 amount);
    event RefundSubmission(address indexed sender, uint256 amount);
    event RefundReceived(uint256 amount);

    uint public constant AUCTION_STARTED = 2;
    uint public constant TRADING_STARTED = 4;

    DutchAuctionInterface public dutchAuction;
    TokenInterface public gnosisToken;
    uint public totalContributions;
    uint public totalTokens;
    uint public totalBalance;
    mapping (address => uint) public contributions;
    Stages public stage;

    enum Stages {
        ContributionsCollection,
        ContributionsSent,
        TokensClaimed
    }

    modifier atStage(Stages _stage) {
        if (stage != _stage)
            throw;
        _;
    }

    function ProxySender(address _dutchAuction)
        public
    {
        if (_dutchAuction == 0) throw;
        dutchAuction = DutchAuctionInterface(_dutchAuction);
        gnosisToken = dutchAuction.gnosisToken();
        if (address(gnosisToken) == 0) throw;
        stage = Stages.ContributionsCollection;
    }

    function()
        public
        payable
    {
        if (msg.sender == address(dutchAuction))
            RefundReceived(msg.value);
        else if (stage == Stages.ContributionsCollection)
            contribute();
        else if(stage == Stages.TokensClaimed)
            transfer();
        else
            throw;
    }

    function contribute()
        public
        payable
        atStage(Stages.ContributionsCollection)
    {
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // External call to notify contribution received - VULNERABILITY: placed before state updates
        if (msg.sender.call.value(0)(bytes4(keccak256("onContributionReceived(uint256)")), msg.value)) {
            // If callback succeeded, record the contribution
            contributions[msg.sender] += msg.value;
            totalContributions += msg.value;
            BidSubmission(msg.sender, msg.value);
        } else {
            // If callback failed, still record but notify about failure
            contributions[msg.sender] += msg.value;
            totalContributions += msg.value;
            BidSubmission(msg.sender, msg.value);
        }
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
    }

    function refund()
        public
        atStage(Stages.ContributionsCollection)
    {
        uint contribution = contributions[msg.sender];
        contributions[msg.sender] = 0;
        totalContributions -= contribution;
        RefundSubmission(msg.sender, contribution);
        if (!msg.sender.send(contribution)) throw;
    }

    function bidProxy()
        public
        atStage(Stages.ContributionsCollection)
        returns(bool)
    {
        // Check auction has started
        if (dutchAuction.stage() != AUCTION_STARTED)
            throw;
        // Send all money to auction contract
        stage = Stages.ContributionsSent;
        dutchAuction.bid.value(this.balance)(0);
        return true;
    }

    function claimProxy()
        public
        atStage(Stages.ContributionsSent)
    {
        // Auction is over
        if (dutchAuction.stage() != TRADING_STARTED)
            throw;
        dutchAuction.claimTokens(0);
        totalTokens = gnosisToken.balanceOf(this);
        totalBalance = this.balance;
        stage = Stages.TokensClaimed;
    }

    function transfer()
        public
        atStage(Stages.TokensClaimed)
        returns (uint amount)
    {
        uint contribution = contributions[msg.sender];
        contributions[msg.sender] = 0;
        // Calc. percentage of tokens for sender
        amount = totalTokens * contribution / totalContributions;
        gnosisToken.transfer(msg.sender, amount);
        // Send possible refund share
        uint refund = totalBalance * contribution / totalContributions;
        if (refund > 0)
            if (!msg.sender.send(refund)) throw;
    }
}