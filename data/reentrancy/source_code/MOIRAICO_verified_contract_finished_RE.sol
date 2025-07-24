/*
 * ===== SmartInject Injection Details =====
 * Function      : finished
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 2 findings
 * Total Found   : 10 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-eth (SWC-107)
 * 2. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by implementing a staged withdrawal system that requires multiple transactions to complete. The vulnerability combines time-based restrictions with per-transaction limits, creating persistent state that can be exploited across multiple function calls.
 * 
 * **Key Changes Made:**
 * 
 * 1. **Added State Variables** (assume these exist in contract):
 *    - `mapping(address => uint) public withdrawalRequests` - tracks pending withdrawal amounts
 *    - `uint public lastWithdrawalTime` - enforces time delays between withdrawals
 *    - `uint public withdrawalDelay` - minimum time between withdrawal attempts
 *    - `uint public maxWithdrawalPerTx` - maximum amount per transaction
 * 
 * 2. **Multi-Transaction Flow**:
 *    - First transaction: Initializes withdrawal request, sets timestamp, returns early
 *    - Subsequent transactions: Process partial withdrawals with time delays
 *    - Final transaction: Transfers remaining tokens when ETH withdrawal complete
 * 
 * 3. **Reentrancy Vulnerability**:
 *    - External call `beneficiary.send(withdrawAmount)` occurs before state updates
 *    - State variables `withdrawalRequests[beneficiary]` and `currentBalance` updated after external call
 *    - Violates Checks-Effects-Interactions pattern in multi-transaction context
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 
 * 1. **Transaction 1**: Attacker calls `finished()` to initialize withdrawal request
 * 2. **Transaction 2**: After delay, attacker calls `finished()` again, but during `beneficiary.send()`, reenters through fallback
 * 3. **Reentrancy Attack**: In fallback, attacker calls `finished()` again before state is updated
 * 4. **Result**: Can drain more ETH than intended by exploiting the window between external call and state update
 * 
 * **Why Multi-Transaction is Required:**
 * 
 * - The vulnerability cannot be exploited in a single transaction due to the time delay requirement
 * - State must accumulate across transactions (withdrawal requests, timestamps)
 * - The reentrancy window only opens after the initial setup transaction
 * - Each transaction builds on state from previous transactions, creating a stateful exploitation path
 * 
 * This creates a realistic vulnerability pattern where the withdrawal system's complexity introduces a multi-transaction reentrancy attack surface.
 */
pragma solidity ^0.4.16;
/*
Moira ICO Contract

MOI is an ERC-20 Token Standar Compliant

Contract developer: Fares A. Akel C.
f.antonio.akel@gmail.com
MIT PGP KEY ID: 078E41CB
*/

/**
 * @title SafeMath by OpenZeppelin
 * @dev Math operations with safety checks that throw on error
 */
library SafeMath {

    function mul(uint256 a, uint256 b) internal pure returns (uint256) {
        uint256 c = a * b;
        assert(a == 0 || c / a == b);
        return c;
    }

    function add(uint256 a, uint256 b) internal pure returns (uint256) {
        uint256 c = a + b;
        assert(c >= a);
        return c;
    }
}

contract token { //Token functions definition

    function balanceOf(address _owner) public constant returns (uint256 balance);
    function transfer(address _to, uint256 _value) public returns (bool success);

    }
contract MOIRAICO {
    //This ico have 3 stages
    enum State {
        Preico,
        Ico,
        Successful
    }
    
    State public state = State.Preico; //Set initial stage
    uint startTime = now; //block-time when it was deployed

    //We use an aproximation of 1 eth = 290$ for this price calculation
    //List of prices for each stage, as both, eth and moi have 18 decimal, its a direct factor
    uint[9] tablePrices = [
    63800,70180,76560, //+10%,+20%,+30%
    58000,63800,70180, //+0%,+10%,+20%
    32200,35420,38640  //+0%,+10%,+20%
    ];

    mapping (address => uint) balances; //balances mapping
    //public variables
    uint public totalRaised;
    uint public currentBalance;
    uint public preICODeadline;
    uint public ICOdeadline;
    uint public completedAt;
    token public tokenReward;
    address public creator;
    address public beneficiary; 
    string public campaignUrl;
    uint constant version = 1;

    // ====== Added variables for withdrawal system =====
    mapping(address => uint) public withdrawalRequests;
    uint public lastWithdrawalTime;
    uint public withdrawalDelay = 1 days; // example value, can be changed
    uint public maxWithdrawalPerTx = 10 ether; // example value, can be changed
    // ================================================

    //events for log

    event LogFundingReceived(address _addr, uint _amount, uint _currentTotal);
    event LogBeneficiaryPaid(address _beneficiaryAddress);
    event LogFundingSuccessful(uint _totalRaised);
    event LogFunderInitialized(
        address _creator,
        address _beneficiary,
        string _url,
        uint256 _preICODeadline,
        uint256 _ICOdeadline);
    event LogContributorsPayout(address _addr, uint _amount);
    // Added missing event
    event LogWithdrawalRequested(address _beneficiary, uint _amount);

    modifier notFinished() {
        require(state != State.Successful);
        _;
    }

    constructor (
        string _campaignUrl,
        token _addressOfTokenUsedAsReward )
        public
    {
        creator = msg.sender;
        beneficiary = msg.sender;
        campaignUrl = _campaignUrl;
        preICODeadline = SafeMath.add(startTime,34 days);
        ICOdeadline = SafeMath.add(preICODeadline,30 days);
        currentBalance = 0;
        tokenReward = token(_addressOfTokenUsedAsReward);
        LogFunderInitialized(
            creator,
            beneficiary,
            campaignUrl,
            preICODeadline,
            ICOdeadline);
    }

    function contribute() public notFinished payable {

        require(msg.value > 1 finney); //minimun contribution

        uint tokenBought;
        totalRaised =SafeMath.add(totalRaised, msg.value);
        currentBalance = totalRaised;
        /**
         * Here price logic is made
         */
        if(state == State.Preico && now < (startTime + 1 days)){ //if we are on preico first day
            if(msg.value < 10 ether){ //if the amount is less than 10 ether
                tokenBought = SafeMath.mul(msg.value,tablePrices[0]);
            }
            else if(msg.value < 20 ether){//if the amount is more than 10 ether and less than 20
                tokenBought = SafeMath.mul(msg.value,tablePrices[1]);
            }
            else{//if the amount is more than 20 ether
                tokenBought = SafeMath.mul(msg.value,tablePrices[2]);
            }
        }
        else if(state == State.Preico) {//if we are on preico normal days
            if(msg.value < 10 ether){ //if the amount is less than 10 ether
                tokenBought = SafeMath.mul(msg.value,tablePrices[3]);
            }
            else if(msg.value < 20 ether){//if the amount is more than 10 ether and less than 20
                tokenBought = SafeMath.mul(msg.value,tablePrices[4]);
            }
            else{//if the amount is more than 20 ether
                tokenBought = SafeMath.mul(msg.value,tablePrices[5]);
            }
        }
        else{//if we are on ico
            if(msg.value < 10 ether){ //if the amount is less than 10 ether
                tokenBought = SafeMath.mul(msg.value,tablePrices[6]);
            }
            else if(msg.value < 20 ether){//if the amount is more than 10 ether and less than 20
                tokenBought = SafeMath.mul(msg.value,tablePrices[7]);
            }
            else{//if the amount is more than 20 ether
                tokenBought = SafeMath.mul(msg.value,tablePrices[8]);
            }
        }

        tokenReward.transfer(msg.sender, tokenBought);
        
        LogFundingReceived(msg.sender, msg.value, totalRaised);
        LogContributorsPayout(msg.sender, tokenBought);
        
        checkIfFundingCompleteOrExpired();
    }

    function checkIfFundingCompleteOrExpired() public {
        
        if(now < ICOdeadline && state!=State.Successful){
            if(now > preICODeadline && state==State.Preico){
                state = State.Ico;    
            }
        }
        else if(now > ICOdeadline && state!=State.Successful) {
            state = State.Successful;
            completedAt = now;
            LogFundingSuccessful(totalRaised);
            finished();  
        }
    }

    function payOut() public {
        require(msg.sender == beneficiary);
        require(beneficiary.send(this.balance));
        LogBeneficiaryPaid(beneficiary);
    }


    function finished() public { //When finished eth and remaining tokens are transfered to beneficiary
        uint remanent;

        require(state == State.Successful);
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Multi-transaction withdrawal system with stateful tracking
        if (withdrawalRequests[beneficiary] == 0) {
            // First transaction: Initialize withdrawal request
            withdrawalRequests[beneficiary] = this.balance;
            lastWithdrawalTime = now;
            LogWithdrawalRequested(beneficiary, this.balance);
            return;
        }
        
        // Subsequent transactions: Process withdrawal with time delay
        require(now >= lastWithdrawalTime + withdrawalDelay);
        require(withdrawalRequests[beneficiary] > 0);
        
        uint withdrawAmount = withdrawalRequests[beneficiary];
        if (withdrawAmount > maxWithdrawalPerTx) {
            withdrawAmount = maxWithdrawalPerTx;
        }
        
        // Vulnerable external call before state update
        require(beneficiary.send(withdrawAmount));
        
        // State updates after external call - vulnerable to reentrancy
        withdrawalRequests[beneficiary] -= withdrawAmount;
        currentBalance -= withdrawAmount;
        
        if (withdrawalRequests[beneficiary] == 0) {
            // Final transaction: Transfer remaining tokens
            remanent = tokenReward.balanceOf(this);
            tokenReward.transfer(beneficiary, remanent);
            currentBalance = 0;
            LogContributorsPayout(beneficiary, remanent);
        }
        
        lastWithdrawalTime = now;
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        LogBeneficiaryPaid(beneficiary);
    }

    function () public payable {
        require(msg.value > 1 finney);
        contribute();
    }
}
