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
 * Total Found   : 9 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-benign (SWC-107)
 * 2. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by:
 * 
 * 1. **Specific Changes Made:**
 *    - Removed the immediate `currentBalance = 0` update and moved it after external calls
 *    - Changed the logic to use `if (this.balance > 0)` instead of unconditional execution
 *    - Created a vulnerable window where state persists between the tokenReward.transfer() and the balance check
 *    - External calls now occur before critical state updates, violating checks-effects-interactions pattern
 * 
 * 2. **Multi-Transaction Exploitation:**
 *    - **Transaction 1**: Legitimate call to finished() transfers tokens to creator and triggers creator.send()
 *    - **Reentrancy Window**: If creator is a malicious contract, it can call finished() again during the send() callback
 *    - **Transaction 2**: The reentrant call finds `this.balance > 0` still true (since currentBalance hasn't been updated yet)
 *    - **State Persistence**: The `currentBalance` variable maintains its value between transactions, allowing multiple withdrawals
 *    - **Accumulated Effect**: Each reentrant call can drain additional funds before state is properly updated
 * 
 * 3. **Why Multiple Transactions Are Required:**
 *    - The vulnerability relies on the persistent state of `this.balance` and `currentBalance` between function calls
 *    - A single transaction cannot exploit this because the state changes need to persist across callback boundaries
 *    - The malicious creator contract needs to receive the callback from `creator.send()` to trigger reentrancy
 *    - Multiple calls accumulate the drainage effect - each call can extract funds while the balance check remains true
 *    - The vulnerability window exists because state updates are deferred until after external interactions
 * 
 * This creates a realistic reentrancy vulnerability that requires the attacker to have control over the creator address and deploy a malicious contract that can receive ETH and call back into the ICO contract during the send() callback, making it a genuine multi-transaction exploit.
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
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        remanent =  tokenReward.balanceOf(this);
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // Vulnerable pattern: external call before state update
        tokenReward.transfer(creator, remanent);
        
        // Allow reentrancy by checking balance instead of state flag
        if (this.balance > 0) {
            // State persists between transactions - vulnerable window
            require(creator.send(this.balance));
            
            // Critical state update moved after external call
            currentBalance = 0;
            
            LogBeneficiaryPaid(creator);
            LogContributorsPayout(creator, remanent);
        }
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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