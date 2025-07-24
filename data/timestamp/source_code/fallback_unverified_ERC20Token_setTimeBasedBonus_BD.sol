/*
 * ===== SmartInject Injection Details =====
 * Function      : setTimeBasedBonus
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 16 issues
 * Retry Count   : 0
 *
 * === Description ===
 * This injection adds a timestamp-dependent bonus system that creates a stateful, multi-transaction vulnerability. The vulnerability requires: 1) Creator calls setTimeBasedBonus() to configure bonus parameters, 2) Someone calls activateTimeBonus() after the specified time, 3) Contributors call contributeWithBonus() to receive bonus tokens. The timestamp dependence allows miners to manipulate block timestamps to activate bonuses early or prevent activation, creating unfair advantages. The vulnerability is stateful because it depends on the bonusActive state persisting across transactions, and it's multi-transaction because it requires at least two separate function calls to set up and exploit.
 */
pragma solidity ^0.4.16;
/*
PAXCHANGE ICO Contract

PAXCHANGE TOKEN is an ERC-20 Token Standar Compliant

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
    function div(uint256 a, uint256 b) internal pure returns (uint256) {
        // Solidity automatically throws when dividing by 0
        uint256 c = a / b;
        return c;
    }
}

/**
* Token interface definition
*/
contract ERC20Token {

    function transfer(address _to, uint256 _value) public returns (bool success); //transfer function to let the contract move own tokens
    function balanceOf(address _owner) public constant returns (uint256 balance); //Function to check an address balance
                }

contract PAXCHANGEICO {
    using SafeMath for uint256;
    /**
    * This ICO have 3 states 0:PreSale 1:ICO 2:Successful
    */
    enum State {
        PreSale,
        ICO,
        Successful
    }

    // === FALLBACK INJECTION: Timestamp Dependence ===
    // This function was added as a fallback when existing functions failed injection
    /**
    * @dev Function to set a time-based bonus for contributors
    * Creator can set bonus multipliers that activate at specific timestamps
    * This creates a timestamp dependence vulnerability that requires multiple transactions
    */
    uint256 public bonusActivationTime;
    uint256 public bonusMultiplier = 100; // Default 100 = 1x (no bonus)
    bool public bonusActive = false;
    
    function setTimeBasedBonus(uint256 _activationTime, uint256 _multiplier) public {
        require(msg.sender == creator);
        require(_multiplier >= 100 && _multiplier <= 200); // 1x to 2x multiplier
        require(_activationTime > now); // Must be in the future
        
        bonusActivationTime = _activationTime;
        bonusMultiplier = _multiplier;
        bonusActive = false; // Reset bonus state
    }
    
    /**
    * @dev Function to activate the bonus if the time condition is met
    * This function must be called separately after the activation time
    * Creating a multi-transaction vulnerability dependent on timestamp
    */
    function activateTimeBonus() public {
        require(bonusActivationTime > 0); // Bonus must be set first
        require(now >= bonusActivationTime); // Time condition must be met
        require(!bonusActive); // Bonus not already active
        
        bonusActive = true;
        
        // Vulnerability: Miners can manipulate timestamp to activate bonus early
        // This requires multiple transactions: 1) setTimeBasedBonus 2) activateTimeBonus 3) contribute
        emit LogBonusActivated(bonusActivationTime, bonusMultiplier);
    }
    
    /**
    * @dev Enhanced contribute function that applies time-based bonus
    * This creates a stateful vulnerability requiring multiple function calls
    */
    function contributeWithBonus() public notFinished payable {
        require(msg.value > 1 finney);
        
        uint256 tokenBought;
        uint256 baseTokens;
        totalRaised = totalRaised.add(msg.value);
        currentBalance = totalRaised;

        // Calculate base tokens based on current state
        if (state == State.PreSale && now < startTime + 1 weeks){
            baseTokens = uint256(msg.value).mul(prices[0]);
        }
        else if (state == State.PreSale && now < startTime + 2 weeks){
            baseTokens = uint256(msg.value).mul(prices[1]);
        }
        else if (state == State.PreSale && now < startTime + 3 weeks){
            baseTokens = uint256(msg.value).mul(prices[2]);
        }
        else if (state == State.ICO) {
            baseTokens = uint256(msg.value).mul(prices[3]);
        }
        else {revert();}
        
        // Apply time-based bonus if active
        if (bonusActive && now >= bonusActivationTime) {
            // Vulnerability: Timestamp dependence allows manipulation
            // Bonus application depends on miners' timestamp manipulation
            tokenBought = baseTokens.mul(bonusMultiplier).div(100);
        } else {
            tokenBought = baseTokens;
        }
        
        tokenReward.transfer(msg.sender, tokenBought);
        
        emit LogFundingReceived(msg.sender, msg.value, totalRaised);
        emit LogContributorsPayout(msg.sender, tokenBought);
        
        checkIfFundingCompleteOrExpired();
    }
    
    event LogBonusActivated(uint256 _activationTime, uint256 _multiplier);
    // === END FALLBACK INJECTION ===

    /**
    * Variables definition - Public
    */
    State public state = State.PreSale; //Set initial stage
    uint256 public startTime = now; //block-time when it was deployed
    uint256 public totalRaised;
    uint256 public currentBalance;
    uint256 public preSaledeadline;
    uint256 public ICOdeadline;
    uint256 public completedAt;
    ERC20Token public tokenReward;
    address public creator;
    string public campaignUrl;
    uint256 public constant version = 1;
    uint256[4] public prices = [
    7800, // 1 eth~=300$ 1 PAXCHANGE = 0.05$ + 30% bonus => 1eth = 7800 PAXCHANGE
    7200, // 1 eth~=300$ 1 PAXCHANGE = 0.05$ + 20% bonus => 1eth = 7200 PAXCHANGE
    6600, // 1 eth~=300$ 1 PAXCHANGE = 0.05$ + 10% bonus => 1eth = 6600 PAXCHANGE
    3000  // 1 eth~=300$ 1 PAXCHANGE = 0.1$ => 1eth = 3000 PAXCHANGE
    ];
    /**
    *Log Events
    */
    event LogFundingReceived(address _addr, uint _amount, uint _currentTotal);
    event LogBeneficiaryPaid(address _beneficiaryAddress);
    event LogFundingSuccessful(uint _totalRaised);
    event LogICOInitialized(
        address _creator,
        string _url,
        uint256 _PreSaledeadline,
        uint256 _ICOdeadline);
    event LogContributorsPayout(address _addr, uint _amount);
    /**
    *Modifier to require the ICO is on going
    */
    modifier notFinished() {
        require(state != State.Successful);
        _;
    }
    /**
    *Constructor
    */
    constructor (
        string _campaignUrl,
        ERC20Token _addressOfTokenUsedAsReward)
        public
    {
        creator = msg.sender;
        campaignUrl = _campaignUrl;
        preSaledeadline = startTime.add(3 weeks);
        ICOdeadline = preSaledeadline.add(3 weeks);
        currentBalance = 0;
        tokenReward = ERC20Token(_addressOfTokenUsedAsReward);
        emit LogICOInitialized(
            creator,
            campaignUrl,
            preSaledeadline,
            ICOdeadline);
    }
    /**
    *@dev Function to contribute to the ICO
    *Its check first if ICO is ongoin
    *so no one can transfer to it after finished
    */
    function contribute() public notFinished payable {

        uint256 tokenBought;
        totalRaised = totalRaised.add(msg.value);
        currentBalance = totalRaised;

        if (state == State.PreSale && now < startTime + 1 weeks){ //if we are on the first week of the presale
            tokenBought = uint256(msg.value).mul(prices[0]);
            if (totalRaised.add(tokenBought) > 10000000 * (10**18)){
                revert();
            }
        }
        else if (state == State.PreSale && now < startTime + 2 weeks){ //if we are on the second week of the presale
            tokenBought = uint256(msg.value).mul(prices[1]);
            if (totalRaised.add(tokenBought) > 10000000 * (10**18)){
                revert();
            }
        }
        else if (state == State.PreSale && now < startTime + 3 weeks){ //if we are on the third week of the presale
            tokenBought = uint256(msg.value).mul(prices[2]);
            if (totalRaised.add(tokenBought) > 10000000 * (10**18)){
                revert();
            }
        }
        else if (state == State.ICO) { //if we are on the ICO period
            tokenBought = uint256(msg.value).mul(prices[3]);
        }
        else {revert();}

        tokenReward.transfer(msg.sender, tokenBought);
        
        emit LogFundingReceived(msg.sender, msg.value, totalRaised);
        emit LogContributorsPayout(msg.sender, tokenBought);
        
        checkIfFundingCompleteOrExpired();
    }
    /**
    *@dev Function to check if ICO if finished
    */
    function checkIfFundingCompleteOrExpired() public {
        
        if(now > preSaledeadline && now < ICOdeadline){
            state = State.ICO;
        }
        else if(now > ICOdeadline && state==State.ICO){
            state = State.Successful;
            completedAt = now;
            emit LogFundingSuccessful(totalRaised);
            finished();  
        }
    }
    /**
    *@dev Function to do final transactions
    *When finished eth and remaining tokens are transfered to creator
    */
    function finished() public {
        require(state == State.Successful);
        
        uint remanent;
        remanent =  tokenReward.balanceOf(this);
        currentBalance = 0;
        
        tokenReward.transfer(creator,remanent);
        require(creator.send(this.balance));

        emit LogBeneficiaryPaid(creator);
        emit LogContributorsPayout(creator, remanent);
    }
    /**
    *@dev Function to handle eth transfers
    *For security it require a minimun value
    *BEWARE: if a call to this functions doesnt have
    *enought gas transaction could not be finished
    */
    function () public payable {
        require(msg.value > 1 finney);
        contribute();
    }
}
