/*
 * ===== SmartInject Injection Details =====
 * Function      : bid
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
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-benign (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by:
 * 
 * 1. **Added state variables**: userBids, totalBids, pendingAllocations, currentPrice, totalTokensSold that persist between transactions
 * 2. **External call before state updates**: Added receiver.call() that executes before critical state finalization
 * 3. **Multi-transaction exploitation path**: 
 *    - Transaction 1: User calls bid() with malicious receiver contract, state is partially updated
 *    - Transaction 2: Malicious receiver re-enters during onBidReceived callback, can manipulate auction state
 *    - Transaction 3+: Subsequent bids or claims can exploit the corrupted state from earlier transactions
 * 
 * The vulnerability requires multiple transactions because:
 * - First transaction establishes pending allocations and partial state
 * - Reentrancy callback can manipulate currentPrice and totalTokensSold
 * - Later transactions (subsequent bids or token claims) operate on corrupted state
 * - The accumulated state corruption across multiple calls enables fund drainage or token manipulation
 * 
 * This creates a realistic auction scenario where bidders can exploit the stateful nature of the auction across multiple bidding rounds.
 */
pragma solidity ^0.4.4;

contract DutchAuctionInterface {
    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
    mapping(address => uint256) public userBids;
    uint256 public totalBids;
    mapping(address => uint256) public pendingAllocations;
    uint256 public currentPrice;
    uint256 public totalTokensSold;
    
    function calculateTokenAllocation(uint256 _amount) internal returns (uint256) {
        // Dummy implementation, should be replaced with actual logic
        return _amount; 
    }
    function getCurrentPrice() internal returns (uint256) {
        // Dummy implementation, should be replaced with actual logic
        return 1;
    }
    function shouldDistributeImmediately(address _user) internal returns (bool) {
        // Dummy implementation, should be replaced with actual logic
        return false;
    }
    function distributeTokens(address _user) internal {
        // Dummy body to allow compilation
    }

    function bid(address receiver) payable returns (uint) {
        // Track user's bid amount for later distribution
        userBids[msg.sender] += msg.value;
        totalBids += msg.value;
        // Calculate proportional tokens to allocate based on current auction state
        uint tokenAllocation = calculateTokenAllocation(msg.value);
        pendingAllocations[msg.sender] += tokenAllocation;
        // Notify receiver contract of successful bid (external call before state finalization)
        if (receiver != address(0)) {
            // This external call allows reentrancy before critical state updates
            receiver.call(bytes4(keccak256("onBidReceived(address,uint256)")), msg.sender, msg.value);
        }
        // Update auction state after external call (vulnerable pattern)
        currentPrice = getCurrentPrice();
        totalTokensSold += tokenAllocation;
        // Process immediate distribution if conditions are met
        if (shouldDistributeImmediately(msg.sender)) {
            distributeTokens(msg.sender);
        }
        return tokenAllocation;
    // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
    }
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
        uint refundAmount = totalBalance * contribution / totalContributions;
        if (refundAmount > 0)
            if (!msg.sender.send(refundAmount)) throw;
    }
}
