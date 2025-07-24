/*
 * ===== SmartInject Injection Details =====
 * Function      : claimRefund
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
 * This vulnerability introduces timestamp dependence through a multi-transaction refund mechanism. The exploit requires: 1) First calling requestRefundEligibility() to set a waiting period, 2) Then calling claimRefund() after the timestamp-based waiting period. Miners can manipulate block timestamps to allow early refund claims or prevent refunds by setting timestamps beyond the deadline. The vulnerability is stateful as it depends on the refundEligibleTime mapping persisting between transactions.
 */
pragma solidity ^0.4.18;
// This contract has the burn option
interface token {
    function transfer(address receiver, uint amount);
    function burn(uint256 _value) returns (bool);
    function balanceOf(address _address) returns (uint256);
}
contract owned {
    address public owner;

    function owned() public {
        owner = msg.sender;
    }

    modifier onlyOwner {
        require(msg.sender == owner);
        _;
    }
}

contract SafeMath {
    //internals

    function safeMul(uint a, uint b) internal returns(uint) {
        uint c = a * b;
        assert(a == 0 || c / a == b);
        return c;
    }

    function safeSub(uint a, uint b) internal returns(uint) {
        assert(b <= a);
        return a - b;
    }

    function safeAdd(uint a, uint b) internal returns(uint) {
        uint c = a + b;
        assert(c >= a && c >= b);
        return c;
    }

}

contract BTCxCrowdsale is owned, SafeMath {
    address public beneficiary;
    uint public fundingGoal;
    uint public amountRaised;  //The amount being raised by the crowdsale
    /* the end date of the crowdsale*/
    uint public deadline; /* the end date of the crowdsale*/
    uint public rate; //rate for the crowdsale
    uint public tokenDecimals;
    token public tokenReward; //
    uint public tokensSold = 0;  
    /* the start date of the crowdsale*/
    uint public start; /* the start date of the crowdsale*/
    mapping(address => uint256) public balanceOf;  //Ether deposited by the investor
    // bool fundingGoalReached = false;
    bool crowdsaleClosed = false; //It will be true when the crowsale gets closed

    event GoalReached(address beneficiary, uint capital);
    event FundTransfer(address backer, uint amount, bool isContribution);

    /**
     * Constrctor function
     *
     * Setup the owner
     */
    function BTCxCrowdsale( ) public {
        beneficiary = 0x781AC8C2D6dc017c4259A1f06123659A4f6dFeD8;
        rate = 2; 
        tokenDecimals=8;
        fundingGoal = 14700000 * (10 ** tokenDecimals); 
        start = 1512831600; //      12/11/2017 @ 2:00pm (UTC)
        deadline =1515628740; //    01/10/2018 @ 11:59pm (UTC)
        tokenReward = token(0x5A82De3515fC4A4Db9BA9E869F269A1e85300092); //Token address. Modify by the current token address

        // === FALLBACK INJECTION: Timestamp Dependence ===
        // This function was added as a fallback when existing functions failed injection
        // Moved variable declarations outside of the constructor
        // === END FALLBACK INJECTION ===

    }    

    // === FALLBACK INJECTION: Timestamp Dependence ===
    // Moved here from constructor
    uint public refundDeadline;
    mapping(address => uint256) public refundClaimed;
    mapping(address => uint256) public refundEligibleTime;

    /**
     * Set refund deadline - only owner can set this
     */
    function setRefundDeadline(uint _refundDeadline) onlyOwner {
        refundDeadline = _refundDeadline;
    }
    
    /**
     * Request refund eligibility - investors must call this first
     */
    function requestRefundEligibility() {
        require(crowdsaleClosed == true);
        require(balanceOf[msg.sender] > 0);
        require(refundClaimed[msg.sender] == 0);
        
        // Set eligibility time to current timestamp + 7 days
        refundEligibleTime[msg.sender] = now + 7 days;
    }
    
    /**
     * Claim refund - vulnerable to timestamp manipulation
     * Investors can claim refund after waiting period
     */
    function claimRefund() {
        require(crowdsaleClosed == true);
        require(balanceOf[msg.sender] > 0);
        require(refundClaimed[msg.sender] == 0);
        require(refundEligibleTime[msg.sender] != 0);
        
        // Vulnerable: relies on 'now' timestamp which can be manipulated by miners
        // Miners can manipulate timestamp to allow early refund claims
        require(now >= refundEligibleTime[msg.sender]);
        
        // Additional vulnerable check: if refund deadline is set and passed
        if (refundDeadline != 0) {
            require(now <= refundDeadline);
        }
        
        uint refundAmount = balanceOf[msg.sender];
        balanceOf[msg.sender] = 0;
        refundClaimed[msg.sender] = refundAmount;
        
        msg.sender.transfer(refundAmount);
        FundTransfer(msg.sender, refundAmount, false);
    }
    // === END FALLBACK INJECTION ===

    /**
     * Fallback function
     *
     * The function without name is the default function that is called whenever anyone sends funds to a contract
     */
    function () payable {
        uint amount = msg.value;  //amount received by the contract
        uint numTokens; //number of token which will be send to the investor
        numTokens = getNumTokens(amount);   //It will be true if the soft capital was reached
        require(numTokens>0 && !crowdsaleClosed && now > start && now < deadline);
        balanceOf[msg.sender] = safeAdd(balanceOf[msg.sender], amount);
        amountRaised = safeAdd(amountRaised, amount); //Amount raised increments with the amount received by the investor
        tokensSold += numTokens; //Tokens sold increased too
        tokenReward.transfer(msg.sender, numTokens); //The contract sends the corresponding tokens to the investor
        beneficiary.transfer(amount);               //Forward ether to beneficiary
        FundTransfer(msg.sender, amount, true);
    }
    /*
    It calculates the amount of tokens to send to the investor 
    */
    function getNumTokens(uint _value) internal returns(uint numTokens) {
        numTokens = safeMul(_value,rate)/(10 ** tokenDecimals); //Number of tokens to give is equal to the amount received by the rate 
        return numTokens;
    }

    modifier afterDeadline() { if (now >= deadline) _; }

    /**
     * Check if goal was reached
     *
     * Checks if the goal or time limit has been reached and ends the campaign and burn the tokens
     */
    function checkGoalReached() afterDeadline {
        require(msg.sender == owner); //Checks if the one who executes the function is the owner of the contract
        if (tokensSold >=fundingGoal){
            GoalReached(beneficiary, amountRaised);
        }
        tokenReward.burn(tokenReward.balanceOf(this)); //Burns all the remaining tokens in the contract 
        crowdsaleClosed = true; //The crowdsale gets closed if it has expired
    }
}
