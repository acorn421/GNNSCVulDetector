/*
 * ===== SmartInject Injection Details =====
 * Function      : claimProxy
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 1 findings
 * Total Found   : 2 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-benign (SWC-107)
 *
 * === Description ===
 * **Specific Changes Made:**
 * 
 * 1. **State Update Timing**: Moved the stage update to occur BEFORE the external call, creating a window where the contract believes tokens are claimed but external interactions can still occur.
 * 
 * 2. **Conditional Balance Updates**: Changed the balance updates to only increase totalTokens and totalBalance if the new values are greater than existing ones. This creates an accumulation mechanism that requires multiple transactions to build up.
 * 
 * 3. **Removed Atomic State Protection**: The original code updated all state variables at once after the external call. The modified version allows partial state updates and re-entry opportunities.
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 
 * **Transaction 1 (Setup):**
 * - Attacker calls claimProxy() normally
 * - Stage is set to TokensClaimed, but external call dutchAuction.claimTokens(0) is made
 * - If dutchAuction is malicious/compromised, it can call back into claimProxy()
 * - However, the atStage(Stages.ContributionsSent) modifier now fails since stage was already changed
 * 
 * **Transaction 2 (Exploitation):**
 * - Attacker needs to manipulate the contract state externally (through other functions or direct state manipulation if possible)
 * - Or exploit race conditions where multiple users call claimProxy() simultaneously
 * - The conditional balance updates mean that multiple successful claims can accumulate totalTokens and totalBalance
 * 
 * **Transaction 3+ (Amplification):**
 * - Through repeated interactions with a malicious dutchAuction contract
 * - Each interaction can potentially increase the recorded balances beyond what should be possible
 * - This creates inflated totalTokens and totalBalance values that affect all subsequent transfer() operations
 * 
 * **Why Multi-Transaction is Required:**
 * 
 * 1. **State Accumulation**: The vulnerability relies on the conditional balance updates (`if (newTokenBalance > totalTokens)`) which allows balances to accumulate across multiple calls rather than being set to exact values.
 * 
 * 2. **External Contract Coordination**: The exploit requires coordination with the dutchAuction contract across multiple transactions to manipulate the balance readings.
 * 
 * 3. **Timing Dependencies**: The vulnerability depends on the specific order and timing of state changes that can only be achieved through multiple transaction sequences.
 * 
 * 4. **Cross-Function Impact**: The inflated balances from multiple claimProxy() calls will affect all subsequent transfer() operations, creating a systemic vulnerability that compounds over time.
 * 
 * This creates a realistic reentrancy vulnerability where the damage accumulates over multiple transactions, making it much more dangerous than a simple single-transaction reentrancy attack.
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
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Mark as claimed but allow re-entry if tokens haven't been fully processed
        if (stage == Stages.ContributionsSent) {
            stage = Stages.TokensClaimed;
        }
        
        // External call that can trigger reentrancy
        dutchAuction.claimTokens(0);
        
        // Update balances after external call - vulnerable to manipulation
        uint newTokenBalance = gnosisToken.balanceOf(this);
        uint newEthBalance = this.balance;
        
        // Only update if balances increased (allowing accumulated claims)
        if (newTokenBalance > totalTokens) {
            totalTokens = newTokenBalance;
        }
        if (newEthBalance > totalBalance) {
            totalBalance = newEthBalance;
        }
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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