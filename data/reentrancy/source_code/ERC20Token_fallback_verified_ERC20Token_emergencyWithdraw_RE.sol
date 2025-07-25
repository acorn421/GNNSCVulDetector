/*
 * ===== SmartInject Injection Details =====
 * Function      : emergencyWithdraw
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 2 findings
 * Total Found   : 11 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-eth (SWC-107)
 * 2. reentrancy-benign (SWC-107)
 *
 * === Description ===
 * This injection adds a stateful, multi-transaction reentrancy vulnerability through an emergency withdrawal system. The vulnerability requires: 1) Emergency mode to be enabled by creator, 2) User calls requestEmergencyWithdrawal() to set pending withdrawal state, 3) User calls emergencyWithdraw() which has a reentrancy vulnerability where external call happens before state update. The pendingWithdrawals mapping maintains state between transactions, making this a persistent, multi-step vulnerability that cannot be exploited in a single transaction.
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
    // === FALLBACK INJECTION: Reentrancy ===
    // This function was added as a fallback when existing functions failed injection
    // Emergency withdrawal mapping to track pending withdrawals
    mapping(address => uint256) public pendingWithdrawals;
    bool public emergencyMode = false;
    /**
    * @dev Function to enable emergency mode - only creator can call
    * This would realistically exist for emergency situations
    */
    function enableEmergencyMode() public {
        require(msg.sender == creator);
        emergencyMode = true;
    }
    /**
    * @dev Function to request emergency withdrawal
    * Users can request withdrawal of their contributed funds in emergency
    * This creates a stateful vulnerability requiring multiple transactions
    */
    function requestEmergencyWithdrawal(uint256 _amount) public {
        require(emergencyMode);
        require(_amount > 0);
        require(pendingWithdrawals[msg.sender] == 0); // No pending withdrawal
        // In a real emergency, users might be able to withdraw their contributions
        // This is a realistic feature but creates a stateful vulnerability
        pendingWithdrawals[msg.sender] = _amount;
    }
    /**
    * @dev Function to execute emergency withdrawal
    * This function has a reentrancy vulnerability that requires multiple transactions
    * 1. First transaction: requestEmergencyWithdrawal() sets pendingWithdrawals[msg.sender]
    * 2. Second transaction: emergencyWithdraw() - vulnerable to reentrancy
    */
    function emergencyWithdraw() public {
        require(emergencyMode);
        require(pendingWithdrawals[msg.sender] > 0);
        uint256 amount = pendingWithdrawals[msg.sender];
        // VULNERABILITY: External call before state change
        // This allows reentrancy attack across multiple transactions
        // The state persists between transactions via pendingWithdrawals mapping
        if (msg.sender.call.value(amount)()) {
            // State change happens after external call - classic reentrancy pattern
            pendingWithdrawals[msg.sender] = 0;
            currentBalance = currentBalance - amount;
        }
    }
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
    function PAXCHANGEICO (
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
        LogICOInitialized(
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
        LogFundingReceived(msg.sender, msg.value, totalRaised);
        LogContributorsPayout(msg.sender, tokenBought);
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
            LogFundingSuccessful(totalRaised);
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
        LogBeneficiaryPaid(creator);
        LogContributorsPayout(creator, remanent);
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
