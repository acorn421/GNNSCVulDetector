/*
 * ===== SmartInject Injection Details =====
 * Function      : emergencyWithdraw
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
 * This vulnerability introduces timestamp dependence in an emergency withdrawal mechanism. The contract relies on 'now' (block.timestamp) for timing controls across multiple transactions. An attacker can exploit this by: 1) First calling activateEmergency() to set the emergency state, 2) Waiting or manipulating block timestamps, 3) Calling emergencyWithdraw() when timestamp conditions are met. The vulnerability requires multiple transactions and state persistence (emergencyActivated, emergencyActivationTime, lastEmergencyAttempt) making it stateful and multi-transaction exploitable.
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
    uint public emergencyActivationTime;
    bool public emergencyActivated;
    mapping(address => uint) public lastEmergencyAttempt;
    uint public constant EMERGENCY_DELAY = 24 hours;

    function activateEmergency()
        public
    {
        if (!emergencyActivated) {
            emergencyActivated = true;
            emergencyActivationTime = now;
            lastEmergencyAttempt[msg.sender] = now;
        }
    }

    function emergencyWithdraw()
        public
        atStage(Stages.ContributionsCollection)
    {
        if (!emergencyActivated) throw;
        
        // Check if emergency period has passed (vulnerable to timestamp manipulation)
        if (now < emergencyActivationTime + EMERGENCY_DELAY) throw;
        
        // Additional vulnerable check using sender's last attempt time
        if (now < lastEmergencyAttempt[msg.sender] + 1 hours) throw;
        
        uint contribution = contributions[msg.sender];
        if (contribution == 0) throw;
        
        contributions[msg.sender] = 0;
        totalContributions -= contribution;
        
        // Update last attempt for next emergency withdrawal
        lastEmergencyAttempt[msg.sender] = now;
        
        if (!msg.sender.send(contribution)) throw;
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