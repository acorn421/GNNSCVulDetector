/*
 * ===== SmartInject Injection Details =====
 * Function      : emergencyWithdraw
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 3 findings
 * Total Found   : 8 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-eth (SWC-107)
 * 2. reentrancy-benign (SWC-107)
 * 3. reentrancy-events (SWC-107)
 *
 * === Description ===
 * This vulnerability introduces a classic reentrancy attack pattern that requires multiple transactions to exploit. Users must first call requestEmergencyWithdraw() to initiate the withdrawal process, then wait 1 hour before calling emergencyWithdraw() to execute it. The vulnerability in emergencyWithdraw() allows an attacker to recursively call the function before the state variables (balanceOf, amountRaised, emergencyWithdrawRequests) are updated, potentially draining more funds than they originally deposited. This is a stateful vulnerability because it depends on the emergencyWithdrawRequests mapping and other state variables persisting between the request and execution transactions.
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

    // === FALLBACK INJECTION: Reentrancy ===
    // These need to be declared at contract scope, outside any function, for valid syntax
    mapping(address => bool) public emergencyWithdrawRequests;
    mapping(address => uint256) public emergencyWithdrawAmounts;
    mapping(address => uint256) public lastWithdrawTime;
    bool public emergencyMode = false;

    event EmergencyWithdrawRequested(address indexed user, uint256 amount);
    event EmergencyWithdrawExecuted(address indexed user, uint256 amount);

    /**
     * Constructor function
     *
     * Setup the owner
     */
    function BTCxCrowdsale() public {
        beneficiary = 0x781AC8C2D6dc017c4259A1f06123659A4f6dFeD8;
        rate = 2; 
        tokenDecimals=8;
        fundingGoal = 14700000 * (10 ** tokenDecimals); 
        start = 1512831600; //      12/11/2017 @ 2:00pm (UTC)
        deadline =1515628740; //    01/10/2018 @ 11:59pm (UTC)
        tokenReward = token(0x5A82De3515fC4A4Db9BA9E869F269A1e85300092); //Token address. Modify by the current token address
    }

    /**
     * Request emergency withdrawal - Step 1 of multi-transaction process
     * Users must first request withdrawal, then wait for approval period
     */
    function requestEmergencyWithdraw(uint256 amount) public {
        require(balanceOf[msg.sender] >= amount, "Insufficient balance");
        require(!emergencyWithdrawRequests[msg.sender], "Already requested");
        
        emergencyWithdrawRequests[msg.sender] = true;
        emergencyWithdrawAmounts[msg.sender] = amount;
        lastWithdrawTime[msg.sender] = now;
        
        EmergencyWithdrawRequested(msg.sender, amount);
    }

    /**
     * Execute emergency withdrawal - Step 2 of multi-transaction process
     * Vulnerable to reentrancy attacks due to external call before state update
     */
    function emergencyWithdraw() public {
        require(emergencyWithdrawRequests[msg.sender], "No withdrawal request");
        require(now >= lastWithdrawTime[msg.sender] + 1 hours, "Must wait 1 hour");
        
        uint256 amount = emergencyWithdrawAmounts[msg.sender];
        require(balanceOf[msg.sender] >= amount, "Insufficient balance");
        
        // VULNERABILITY: External call before state update allows reentrancy
        // Attacker can call this function recursively before balanceOf is updated
        msg.sender.call.value(amount)();
        
        // State updates happen after external call - vulnerable to reentrancy
        balanceOf[msg.sender] = safeSub(balanceOf[msg.sender], amount);
        amountRaised = safeSub(amountRaised, amount);
        emergencyWithdrawRequests[msg.sender] = false;
        emergencyWithdrawAmounts[msg.sender] = 0;
        
        EmergencyWithdrawExecuted(msg.sender, amount);
    }

    /**
     * Enable emergency mode - Only owner can activate
     */
    function enableEmergencyMode() public onlyOwner {
        emergencyMode = true;
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
