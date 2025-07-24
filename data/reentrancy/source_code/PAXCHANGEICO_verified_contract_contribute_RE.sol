/*
 * ===== SmartInject Injection Details =====
 * Function      : contribute
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 5 findings
 * Total Found   : 12 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-benign (SWC-107)
 * 3. reentrancy-benign (SWC-107)
 * ... and 2 more
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by:
 * 1. Moving state updates (totalRaised, currentBalance) to AFTER external calls
 * 2. Adding a callback mechanism that calls external contracts during contribution processing
 * 3. Using stale state (oldTotalRaised) for funding limit checks while actual state updates happen later
 * 4. Creating a window where external contracts can re-enter with inconsistent state
 * 
 * **Multi-Transaction Exploitation:**
 * - Transaction 1: Attacker deploys malicious contract with onContributionReceived callback
 * - Transaction 2: Attacker calls contribute() → triggers callback → malicious contract calls contribute() again
 * - The reentrancy occurs between token transfer and state update, allowing multiple contributions to be processed with the same oldTotalRaised value
 * - This enables bypassing funding limits and potentially draining more tokens than intended
 * 
 * **Why Multi-Transaction Required:**
 * - The vulnerability requires a malicious contract to be deployed first (Transaction 1)
 * - The actual exploitation happens when the callback mechanism is triggered (Transaction 2)  
 * - The state inconsistency persists across the callback execution, allowing the reentrancy to succeed
 * - Without the callback contract deployment and the specific sequence of calls, the vulnerability cannot be exploited
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
    constructor(
        string _campaignUrl,
        ERC20Token _addressOfTokenUsedAsReward) public
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
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        uint256 oldTotalRaised = totalRaised;
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        if (state == State.PreSale && now < startTime + 1 weeks){ //if we are on the first week of the presale
            tokenBought = uint256(msg.value).mul(prices[0]);
            // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
            if (oldTotalRaised.add(tokenBought) > 10000000 * (10**18)){
            // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
                revert();
            }
        }
        else if (state == State.PreSale && now < startTime + 2 weeks){ //if we are on the second week of the presale
            tokenBought = uint256(msg.value).mul(prices[1]);
            // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
            if (oldTotalRaised.add(tokenBought) > 10000000 * (10**18)){
            // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
                revert();
            }
        }
        else if (state == State.PreSale && now < startTime + 3 weeks){ //if we are on the third week of the presale
            tokenBought = uint256(msg.value).mul(prices[2]);
            // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
            if (oldTotalRaised.add(tokenBought) > 10000000 * (10**18)){
            // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
                revert();
            }
        }
        else if (state == State.ICO) { //if we are on the ICO period
            tokenBought = uint256(msg.value).mul(prices[3]);
        }
        else {revert();}

        tokenReward.transfer(msg.sender, tokenBought);
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // Notify contributor callback contract if it exists
        if (isContract(msg.sender)) {
            msg.sender.call(abi.encodeWithSignature("onContributionReceived(uint256,uint256)", msg.value, tokenBought));
            // Continue regardless of callback success
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        emit LogFundingReceived(msg.sender, msg.value, totalRaised);
        emit LogContributorsPayout(msg.sender, tokenBought);
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // Update state after all external interactions
        totalRaised = totalRaised.add(msg.value);
        currentBalance = totalRaised;
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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
    // Helper to detect if an address is a contract
    function isContract(address _addr) internal view returns (bool res) {
        uint size;
        assembly { size := extcodesize(_addr) }
        res = (size > 0);
    }
}
