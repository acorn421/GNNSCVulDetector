/*
 * ===== SmartInject Injection Details =====
 * Function      : transfer
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 1 findings
 * Total Found   : 4 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-eth (SWC-107)
 *
 * === Description ===
 * **VULNERABILITY INJECTION DETAILS:**
 * 
 * **1. Specific Changes Made:**
 * - **Critical State Update Moved**: The line `contributions[msg.sender] = 0;` was moved from the beginning of the function to the very end, after all external calls
 * - **Violation of Checks-Effects-Interactions**: The function now performs external calls (`gnosisToken.transfer()` and `msg.sender.send()`) before updating the critical state variable
 * - **Preserved Function Logic**: All calculations and core functionality remain identical to maintain realistic behavior
 * 
 * **2. Multi-Transaction Exploitation Scenario:**
 * 
 * **Transaction 1 - Initial Setup:**
 * - User calls `contribute()` multiple times to accumulate a significant contribution balance
 * - User deploys a malicious contract with a fallback function or implements `onTokenReceived` callback
 * 
 * **Transaction 2 - First Withdrawal:**
 * - User calls `transfer()` from their malicious contract
 * - Function reads `contributions[msg.sender]` (still non-zero)
 * - Calculates token amount and refund based on contribution
 * - Calls `gnosisToken.transfer(msg.sender, amount)` - if token has callback, triggers reentrancy
 * - During the external call, malicious contract re-enters `transfer()`
 * 
 * **Transaction 3 - Reentrancy Exploitation:**
 * - Re-entrant call finds `contributions[msg.sender]` still unchanged (hasn't been zeroed yet)
 * - Calculates the same token amount and refund again
 * - Performs another token transfer and ETH send
 * - This can continue until gas runs out or balances are drained
 * 
 * **Transaction 4+ - Continued Exploitation:**
 * - If the malicious contract is sophisticated, it can manage gas usage and exit/re-enter strategically
 * - Each re-entrant call can extract the same amount of tokens and ETH
 * - The vulnerability is exploitable until the contract runs out of tokens or ETH
 * 
 * **3. Why Multiple Transactions Are Required:**
 * 
 * **State Accumulation Dependency:**
 * - The vulnerability depends on prior calls to `contribute()` to build up `contributions[msg.sender]`
 * - Without previous contribution history, there's nothing to exploit
 * 
 * **Reentrancy Setup Requirement:**
 * - The attacker must deploy a malicious contract in a separate transaction
 * - The malicious contract needs specific fallback or callback functions to exploit the reentrancy
 * 
 * **Gas Limitation Enforcement:**
 * - Single transaction gas limits prevent infinite reentrancy
 * - Practical exploitation requires multiple transactions to extract maximum value
 * - The attacker needs to strategically manage gas consumption across multiple calls
 * 
 * **External Call Dependency:**
 * - The vulnerability only triggers when external calls (token transfer or ETH send) invoke the attacker's contract
 * - This requires the attacker's contract to be the recipient, necessitating separate setup transactions
 * 
 * **4. Realistic Exploitation Impact:**
 * - Attacker can drain tokens proportional to their contribution multiple times
 * - ETH refunds can be claimed repeatedly
 * - Other users' legitimate withdrawals are compromised as contract balances are depleted
 * - The vulnerability exploits the natural trust in external token contracts and ETH transfers
 * 
 * This injection creates a realistic, stateful reentrancy vulnerability that requires careful multi-transaction orchestration to exploit, making it an excellent example for security research and testing defensive tools.
 */
pragma solidity ^0.4.4;

contract DutchAuctionInterface {
    function bid(address receiver) public payable returns (uint);
    function claimTokens(address receiver) public;
    function stage() public returns (uint);
    TokenInterface public gnosisToken;
}

contract TokenInterface {
    function transfer(address to, uint value) public returns (bool);
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

    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
    function transfer()
        public
        atStage(Stages.TokensClaimed)
        returns (uint amount)
    {
        uint contribution = contributions[msg.sender];
        // Calc. percentage of tokens for sender
        amount = totalTokens * contribution / totalContributions;
        gnosisToken.transfer(msg.sender, amount);
        // Send possible refund share
        uint refundAmount = totalBalance * contribution / totalContributions;
        if (refundAmount > 0) {
            if (!msg.sender.send(refundAmount)) throw;
        }
        // STATE UPDATE MOVED TO AFTER EXTERNAL CALLS - VULNERABILITY!
        contributions[msg.sender] = 0;
    }
    // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
}
