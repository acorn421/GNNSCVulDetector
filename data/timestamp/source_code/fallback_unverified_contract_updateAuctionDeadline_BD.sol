/*
 * ===== SmartInject Injection Details =====
 * Function      : updateAuctionDeadline
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 4 issues
 * Retry Count   : 0
 *
 * === Description ===
 * This function introduces a timestamp dependence vulnerability where the auction deadline can be manipulated through multiple transactions. An attacker can exploit this by: 1) First calling updateAuctionDeadline() to set an initial deadline, 2) Waiting for favorable market conditions or accumulating more funds, 3) Calling updateAuctionDeadline() again within the 1-hour window to extend the deadline further. This creates a stateful vulnerability requiring multiple transactions and state persistence between calls.
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

    // === FALLBACK INJECTION: Timestamp Dependence ===
    // This function was added as a fallback when existing functions failed injection
    uint public auctionDeadline;
    mapping(address => uint) public lastDeadlineUpdate;

    function updateAuctionDeadline(uint _newDeadline)
        public
        atStage(Stages.ContributionsCollection)
    {
        // Allow updating deadline if current time is within 1 hour of previous deadline
        if (auctionDeadline != 0 && now > auctionDeadline + 1 hours)
            throw;
        
        // Store when this address last updated the deadline
        lastDeadlineUpdate[msg.sender] = now;
        auctionDeadline = _newDeadline;
    }
    // === END FALLBACK INJECTION ===

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
        contributions[msg.sender] += msg.value;
        totalContributions += msg.value;
        BidSubmission(msg.sender, msg.value);
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