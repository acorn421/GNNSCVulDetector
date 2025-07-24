/*
 * ===== SmartInject Injection Details =====
 * Function      : claimProxy
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
 * This vulnerability injection introduces a timestamp-dependent token decay mechanism that creates a stateful, multi-transaction exploit scenario. The vulnerability operates as follows:
 * 
 * **SPECIFIC CHANGES MADE:**
 * 1. Added two new state variables (claimWindowStart, claimWindowEnd) that get set on first execution using block.timestamp
 * 2. Introduced a time-based token decay system that reduces totalTokens based on elapsed time
 * 3. The decay calculation uses block.timestamp differences to determine token reduction rates
 * 
 * **MULTI-TRANSACTION EXPLOITATION:**
 * 1. **Transaction 1 (Block N)**: First user calls claimProxy(), setting claimWindowStart to block.timestamp of Block N
 * 2. **Transaction 2+ (Block N+X)**: Subsequent calls in later blocks experience token decay based on manipulated timestamps
 * 3. **Miner Exploitation**: Miners can manipulate block.timestamp in Block N to artificially extend or compress the decay timeline
 * 4. **Front-running**: Attackers can monitor pending claimProxy calls and manipulate their own transaction timing
 * 
 * **WHY MULTI-TRANSACTION REQUIRED:**
 * - The vulnerability requires the claimWindowStart to be set in state during the first transaction
 * - Subsequent transactions (potentially from different users) are affected by the timestamp stored from the first call
 * - The exploit depends on time differences between multiple blocks/transactions
 * - A single transaction cannot manipulate both the initial timestamp setting AND benefit from the decay mechanism
 * - The stateful nature means the vulnerability compounds across multiple user interactions
 * 
 * **REALISTIC ATTACK SCENARIOS:**
 * - Miners can set favorable timestamps in the first claimProxy call, affecting all subsequent users
 * - Attackers can delay their claims strategically while manipulating network conditions
 * - The 48-hour window creates a predictable timeframe for exploitation
 * - Token decay affects the entire pool, creating systemic risk across multiple transactions
 */
pragma solidity ^0.4.4;

contract DutchAuctionInterface {
    function bid(address receiver) public payable returns (uint);
    function claimTokens(address receiver) public;
    function stage() public returns (uint);
    function gnosisToken() public returns (TokenInterface);
    // Removed second gnosisToken declaration to resolve redeclaration error
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

    // ===== Added state variables for vulnerability injection =====
    uint public claimWindowStart;
    uint public claimWindowEnd;
    // ===== End of additions =====

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

    // Updated to valid constructor syntax for pragma ^0.4.4
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
            RefundReceived(msg.value); // emit not needed for >=0.4.0 <0.4.21
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
        dutchAuction.bid.value(address(this).balance)(0);
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
        totalBalance = address(this).balance;
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        // Set claim window based on block timestamp - vulnerability injection
        if (claimWindowStart == 0) {
            claimWindowStart = block.timestamp;
            claimWindowEnd = block.timestamp + 172800; // 48 hour window
        }
        // Apply time-based token decay to incentivize early claims
        uint timePassed = block.timestamp - claimWindowStart;
        if (timePassed > 86400) { // After 24 hours, start reducing available tokens
            uint decayRate = (timePassed - 86400) * 100 / 86400; // 1% per hour after first day
            if (decayRate > 50) decayRate = 50; // Max 50% reduction
            totalTokens = totalTokens * (100 - decayRate) / 100;
        }
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
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
        uint transferRefund = totalBalance * contribution / totalContributions;
        if (transferRefund > 0)
            if (!msg.sender.send(transferRefund)) throw;
    }
}
