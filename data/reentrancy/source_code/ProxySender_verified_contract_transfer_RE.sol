/*
 * ===== SmartInject Injection Details =====
 * Function      : transfer
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
 * 2. reentrancy-benign (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by:
 * 
 * 1. **Added State Variables**: Introduced `partialWithdrawals` and `processedWithdrawals` mappings to track withdrawal state across transactions
 * 2. **Moved State Updates After External Calls**: Critical state cleanup (`contributions[msg.sender] = 0`) now happens AFTER external calls to token contract and ETH send
 * 3. **Added Partial Withdrawal Logic**: Users can now have "partial" withdrawals that persist across transactions, creating exploitable state
 * 4. **Failure Handling Creates Persistent State**: When ETH send fails, the function marks it as a partial withdrawal, allowing the user to retry in subsequent transactions while preserving their contribution amount
 * 
 * **Multi-Transaction Exploitation Scenario**:
 * - **Transaction 1**: User calls transfer(), receives tokens, but makes ETH send fail intentionally (e.g., by having a fallback function that reverts). Their contribution remains in `partialWithdrawals`.
 * - **Transaction 2**: User calls transfer() again, now using the partial withdrawal path. They can receive tokens again because state wasn't properly cleaned up.
 * - **Transaction 3+**: User can continue exploiting the persistent state across multiple transactions.
 * 
 * **Why Multiple Transactions Are Required**:
 * - The vulnerability relies on the persistent state in `partialWithdrawals` that accumulates across failed transactions
 * - A single transaction cannot exploit this because the state persistence happens between transaction boundaries
 * - The attack requires intentionally failing the ETH send in one transaction, then exploiting the preserved state in subsequent transactions
 * 
 * This creates a realistic reentrancy vulnerability that requires careful state management across multiple transactions to exploit, making it a sophisticated multi-transaction attack vector.
 */
pragma solidity ^0.4.4;

contract DutchAuctionInterface {
    function bid(address receiver) public payable returns (uint);
    function claimTokens(address receiver) public;
    function stage() public returns (uint);
    function gnosisToken() public returns (TokenInterface);
}

contract TokenInterface {
    function transfer(address to, uint256 value) public returns (bool success);
    function balanceOf(address owner) public constant returns (uint256 balance);
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
    mapping (address => uint) public partialWithdrawals;
    mapping (address => bool) public processedWithdrawals;
    Stages public stage;

    enum Stages {
        ContributionsCollection,
        ContributionsSent,
        TokensClaimed
    }

    modifier atStage(Stages _stage) {
        if (stage != _stage)
            revert();
        _;
    }

    function ProxySender(address _dutchAuction)
        public
    {
        if (_dutchAuction == 0) revert();
        dutchAuction = DutchAuctionInterface(_dutchAuction);
        gnosisToken = dutchAuction.gnosisToken();
        if (address(gnosisToken) == 0) revert();
        stage = Stages.ContributionsCollection;
    }

    function()
        public
        payable
    {
        if (msg.sender == address(dutchAuction))
            emit RefundReceived(msg.value);
        else if (stage == Stages.ContributionsCollection)
            contribute();
        else if(stage == Stages.TokensClaimed)
            transfer();
        else
            revert();
    }

    function contribute()
        public
        payable
        atStage(Stages.ContributionsCollection)
    {
        contributions[msg.sender] += msg.value;
        totalContributions += msg.value;
        emit BidSubmission(msg.sender, msg.value);
    }

    function refund()
        public
        atStage(Stages.ContributionsCollection)
    {
        uint contribution = contributions[msg.sender];
        contributions[msg.sender] = 0;
        totalContributions -= contribution;
        emit RefundSubmission(msg.sender, contribution);
        if (!msg.sender.send(contribution)) revert();
    }

    function bidProxy()
        public
        atStage(Stages.ContributionsCollection)
        returns(bool)
    {
        // Check auction has started
        if (dutchAuction.stage() != AUCTION_STARTED)
            revert();
        // Send all money to auction contract
        stage = Stages.ContributionsSent;
        dutchAuction.bid.value(address(this).balance)(0);
        return true;
    }

    function claimProxy()
        public
        atStage(Stages.ContributionsSent)
    {
        // Auction is over
        if (dutchAuction.stage() != TRADING_STARTED)
            revert();
        dutchAuction.claimTokens(0);
        totalTokens = gnosisToken.balanceOf(this);
        totalBalance = address(this).balance;
        stage = Stages.TokensClaimed;
    }

    function transfer()
        public
        atStage(Stages.TokensClaimed)
        returns (uint amount)
    {
        uint contribution = contributions[msg.sender];
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // Check if user has already partially withdrawn
        if (partialWithdrawals[msg.sender] > 0) {
            // Allow continued withdrawal of remaining amount
            contribution = partialWithdrawals[msg.sender];
        }
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        // Calc. percentage of tokens for sender
        amount = totalTokens * contribution / totalContributions;
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // External call BEFORE state updates - vulnerable to reentrancy
        gnosisToken.transfer(msg.sender, amount);
        // Send possible refund share - another external call before state cleanup
        uint refundAmount = totalBalance * contribution / totalContributions;
        if (refundAmount > 0) {
            if (!msg.sender.send(refundAmount)) {
                // On failure, mark as partial withdrawal to allow retry
                partialWithdrawals[msg.sender] = contribution;
                return amount;
            }
        }
        // State cleanup happens AFTER external calls
        contributions[msg.sender] = 0;
        partialWithdrawals[msg.sender] = 0;
        // Update processed status for multi-transaction tracking
        processedWithdrawals[msg.sender] = true;
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
    }
}
