/*
 * ===== SmartInject Injection Details =====
 * Function      : requestRefund
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 1 findings
 * Total Found   : 5 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-eth (SWC-107)
 *
 * === Description ===
 * This vulnerability introduces a multi-transaction reentrancy attack. Users must first call requestRefund() to set their refund status, then call processRefund() in a separate transaction. The processRefund() function is vulnerable to reentrancy because it makes an external call before updating the state variables. An attacker can create a malicious contract that calls processRefund() recursively through the fallback function, draining the contract multiple times before the state is updated.
 */
pragma solidity ^0.4.11;

contract token {
    function transfer(address receiver, uint amount);
    function balanceOf( address _address ) returns(uint256);
}

contract DragonCrowdsale {
    address public beneficiary;
    address public owner;
  
    uint public amountRaised;
    uint public tokensSold;
    uint public deadline;
    uint public price;
    token public tokenReward;
    mapping(address => uint256) public contributions;
    bool crowdSaleStart;
    bool crowdSalePause;
    bool crowdSaleClosed;

   
    event FundTransfer(address participant, uint amount);

    mapping(address => bool) public refundRequested;
    mapping(address => uint256) public refundAmount;
    
    modifier onlyOwner() {
        if (msg.sender != owner) {
            throw;
        }
        _;
    }

    // === FALLBACK INJECTION: Reentrancy ===
    // This function was added as a fallback when existing functions failed injection
    function requestRefund() {
        require(crowdSaleClosed);
        require(contributions[msg.sender] > 0);
        require(!refundRequested[msg.sender]);
        
        refundRequested[msg.sender] = true;
        refundAmount[msg.sender] = contributions[msg.sender];
    }
    
    function processRefund() {
        require(refundRequested[msg.sender]);
        require(refundAmount[msg.sender] > 0);
        
        uint256 amount = refundAmount[msg.sender];
        
        // Vulnerable to reentrancy - external call before state update
        msg.sender.call.value(amount)();
        
        // State updated after external call
        refundAmount[msg.sender] = 0;
        refundRequested[msg.sender] = false;
        contributions[msg.sender] = 0;
    }
    // === END FALLBACK INJECTION ===

    function DragonCrowdsale() {
        beneficiary = msg.sender;
        owner = msg.sender;
        price =  .003333333333333 ether;
        tokenReward = token(0x5b29a6277c996b477d6632E60EEf41268311cE1c);
    }

    function () payable {
        require(!crowdSaleClosed);
        require(!crowdSalePause);
        if ( crowdSaleStart) require( now < deadline );
        uint amount = msg.value;
        contributions[msg.sender] += amount;
        amountRaised += amount;
        tokensSold += amount / price;
        tokenReward.transfer(msg.sender, amount / price);
        FundTransfer(msg.sender, amount );
        beneficiary.transfer( amount );
    }

    // Start this October 27
    function startCrowdsale() onlyOwner  {
        
        crowdSaleStart = true;
        deadline = now + 60 days;
    }

    function endCrowdsale() onlyOwner  {
        
        
        crowdSaleClosed = true;
    }


    function pauseCrowdsale() onlyOwner {
        
        crowdSalePause = true;
        
        
    }

    function unpauseCrowdsale() onlyOwner {
        
        crowdSalePause = false;
        
        
    }
    
    function transferOwnership ( address _newowner ) onlyOwner {
        
        owner = _newowner;
        
    }
    
    function transferBeneficiary ( address _newbeneficiary ) onlyOwner {
        
        beneficiary = _newbeneficiary;
        
    }
    
    function withdrawDragons() onlyOwner{
        
        uint256 balance = tokenReward.balanceOf(address(this));
        
        tokenReward.transfer( beneficiary, balance );
        
        
    }
    
}