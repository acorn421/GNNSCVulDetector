/*
 * ===== SmartInject Injection Details =====
 * Function      : setCustomDeadline
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
 * This vulnerability creates a multi-transaction timestamp dependence attack where: 1) Owner sets a custom deadline buffer, 2) Users request deadline extensions when close to deadline, 3) Owner processes extensions with timestamp-dependent logic that can be manipulated. The vulnerability requires multiple transactions across different functions and maintains state between calls. An attacker (especially a miner) can manipulate block timestamps to either extend or prevent extensions, giving unfair advantages to certain participants.
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

    // === FALLBACK INJECTION: Timestamp Dependence ===
    // This function was added as a fallback when existing functions failed injection
    uint public customDeadlineBuffer;
    bool public customDeadlineActive;
    mapping(address => uint) public userDeadlineRequests;
    
    function setCustomDeadline(uint _bufferHours) onlyOwner {
        customDeadlineBuffer = _bufferHours * 1 hours;
        customDeadlineActive = true;
    }
    
    function requestDeadlineExtension() {
        require(crowdSaleStart);
        require(!crowdSaleClosed);
        require(customDeadlineActive);
        require(now > deadline - customDeadlineBuffer);
        
        userDeadlineRequests[msg.sender] = now;
    }
    
    function processDeadlineExtension() onlyOwner {
        require(customDeadlineActive);
        uint oldDeadline = deadline;
        
        // Owner can manipulate this timestamp-dependent logic
        if (now > deadline - (customDeadlineBuffer / 2)) {
            deadline = now + customDeadlineBuffer;
        }
        
        // Clear all user requests after processing
        // This creates a window where timing manipulation is possible
    }
    // === END FALLBACK INJECTION ===
    
    modifier onlyOwner() {
        if (msg.sender != owner) {
            throw;
        }
        _;
    }

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
