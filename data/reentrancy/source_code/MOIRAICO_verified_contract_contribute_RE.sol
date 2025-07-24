/*
 * ===== SmartInject Injection Details =====
 * Function      : contribute
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 4 findings
 * Total Found   : 10 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-benign (SWC-107)
 * 2. reentrancy-benign (SWC-107)
 * 3. reentrancy-events (SWC-107)
 * ... and 1 more
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by reordering operations to violate the Checks-Effects-Interactions pattern. The external tokenReward.transfer() call now occurs BEFORE updating the critical state variables (totalRaised, currentBalance). This creates a reentrancy window where an attacker can manipulate the persistent state across multiple transactions.
 * 
 * **Specific Changes Made:**
 * 1. **Moved external call before state updates**: The `tokenReward.transfer()` call now happens before `totalRaised` and `currentBalance` are updated
 * 2. **Preserved token calculation logic**: Token calculation still happens first to maintain function behavior
 * 3. **Maintained logging position**: Logs still occur at appropriate times to preserve expected behavior
 * 4. **State updates moved after external call**: Critical state modifications now happen after the vulnerable external call
 * 
 * **Multi-Transaction Exploitation Path:**
 * 1. **Transaction 1**: Attacker calls contribute() with a malicious token contract. The token's transfer() function triggers a callback that re-enters contribute()
 * 2. **Reentrancy Window**: Since totalRaised/currentBalance aren't updated yet, the second call sees the old state values
 * 3. **Transaction 2**: The reentrant call processes using stale state, potentially allowing double-spending of contributions or manipulation of ICO progress
 * 4. **State Accumulation**: Each successful reentrancy accumulates state changes that persist for future transactions
 * 5. **Exploitation Chain**: Multiple transactions can build up exploitable state conditions over time
 * 
 * **Why Multi-Transaction Dependency is Critical:**
 * - The vulnerability requires the external token contract to be malicious and implemented to trigger reentrancy
 * - State persistence between transactions allows accumulation of the exploit effects
 * - The ICO's funding logic depends on totalRaised accumulating over time, making historical state manipulation valuable
 * - An attacker needs multiple contribution cycles to maximize the impact of the state manipulation
 * - The checkIfFundingCompleteOrExpired() call at the end can be manipulated through accumulated state changes
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

    modifier notFinished() {
        require(state != State.Successful);
        _;
    }

    function MOIRAICO (
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
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // Calculate tokens before any state updates
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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

        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // Make external call BEFORE updating state - vulnerable to reentrancy
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        tokenReward.transfer(msg.sender, tokenBought);
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // Log before state update to show activity
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        LogFundingReceived(msg.sender, msg.value, totalRaised);
        LogContributorsPayout(msg.sender, tokenBought);
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // Update state after external call - creates reentrancy window
        totalRaised = SafeMath.add(totalRaised, msg.value);
        currentBalance = totalRaised;
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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
        require(beneficiary.send(this.balance));
        remanent =  tokenReward.balanceOf(this);
        tokenReward.transfer(beneficiary,remanent);

        currentBalance = 0;

        LogBeneficiaryPaid(beneficiary);
        LogContributorsPayout(beneficiary, remanent);
    }

    function () public payable {
        require(msg.value > 1 finney);
        contribute();
    }
}