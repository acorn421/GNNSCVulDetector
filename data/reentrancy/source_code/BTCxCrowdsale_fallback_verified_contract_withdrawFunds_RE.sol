/*
 * ===== SmartInject Injection Details =====
 * Function      : withdrawFunds
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 3 findings
 * Total Found   : 6 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-eth (SWC-107)
 * 2. reentrancy-benign (SWC-107)
 * 3. reentrancy-events (SWC-107)
 *
 * === Description ===
 * This function introduces a multi-transaction reentrancy vulnerability. The vulnerability requires: 1) First transaction to deposit funds via the fallback function, 2) Second transaction to call withdrawFunds which is vulnerable to reentrancy attacks due to external call before state update. The withdrawalPending mapping tracks state between transactions, making this a stateful vulnerability that persists across multiple calls.
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

        // === FALLBACK INJECTION: Reentrancy ===
        // This function was added as a fallback when existing functions failed injection
        // Mapping moved here
        // mapping(address => bool) public withdrawalPending;
        
        // Note: mapping now declared in contract body
    }

    // Mapping for reentrancy protection (vulnerable implementation)
    mapping(address => bool) public withdrawalPending;
    
    /**
     * Emergency withdrawal function for investors
     * Allows investors to withdraw their funds in case of emergency
     */
    function withdrawFunds() public {
        require(balanceOf[msg.sender] > 0, "No funds to withdraw");
        require(!withdrawalPending[msg.sender], "Withdrawal already pending");
        
        withdrawalPending[msg.sender] = true;
        
        uint256 amount = balanceOf[msg.sender];
        
        // External call before state update - vulnerable to reentrancy
        if (msg.sender.call.value(amount)()) {
            balanceOf[msg.sender] = 0;
            amountRaised = safeSub(amountRaised, amount);
            withdrawalPending[msg.sender] = false;
            FundTransfer(msg.sender, amount, false);
        } else {
            withdrawalPending[msg.sender] = false;
            revert("Transfer failed");
        }
    }
    // === END FALLBACK INJECTION ===

    /**
     * Fallback function
     *
     * The function without name is the default function that is called whenever anyone sends funds to a contract
     */
     /*
   
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
