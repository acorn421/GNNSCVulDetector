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
 * Total Found   : 6 issues
 * Retry Count   : 0
 *
 * === Description ===
 * This vulnerability introduces timestamp dependence where the auction deadline can be manipulated by miners who control block timestamps. The vulnerability requires multiple transactions: 1) Initialize deadline, 2) Multiple contributors request extensions, 3) Deadline gets extended based on manipulable timestamp. Miners can manipulate the 'now' timestamp to either trigger or prevent deadline extensions, affecting when auctions close and potentially allowing late bids or preventing legitimate extensions.
 */
pragma solidity ^0.4.4;

contract DutchAuctionInterface {
    function bid(address receiver) public payable returns (uint);
    function claimTokens(address receiver) public;
    function stage() public returns (uint);
    TokenInterface public gnosisToken;
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
    Stages public stage;

    enum Stages {
        ContributionsCollection,
        ContributionsSent,
        TokensClaimed
    }
    // === FALLBACK INJECTION: Timestamp Dependence ===
    // This function was added as a fallback when existing functions failed injection
    uint public auctionDeadline;
    uint public deadlineExtensionCount;
    mapping(address => bool) public hasRequestedExtension;
    
    function initializeDeadline(uint _deadline)
        public
        atStage(Stages.ContributionsCollection)
    {
        require(auctionDeadline == 0); // Can only be set once
        auctionDeadline = _deadline;
        deadlineExtensionCount = 0;
    }
    
    function updateAuctionDeadline()
        public
        atStage(Stages.ContributionsCollection)
        returns (bool extended)
    {
        require(auctionDeadline > 0); // Must be initialized first
        require(!hasRequestedExtension[msg.sender]); // One request per address
        require(contributions[msg.sender] > 0); // Must be a contributor
        
        // Check if current time is close to deadline (within 1 hour)
        if (now > auctionDeadline - 3600 && now < auctionDeadline) {
            hasRequestedExtension[msg.sender] = true;
            deadlineExtensionCount++;
            
            // Extend deadline by 1 hour if multiple people request it
            if (deadlineExtensionCount >= 2) {
                auctionDeadline = now + 3600; // Vulnerable: uses 'now' timestamp
                return true;
            }
        }
        return false;
    }
    
    function checkDeadlineStatus()
        public
        view
        returns (bool isActive, uint timeRemaining)
    {
        if (now >= auctionDeadline) {
            return (false, 0);
        }
        return (true, auctionDeadline - now); // Vulnerable: depends on 'now'
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
