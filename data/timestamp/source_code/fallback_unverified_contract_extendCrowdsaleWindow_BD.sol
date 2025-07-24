/*
 * ===== SmartInject Injection Details =====
 * Function      : extendCrowdsaleWindow
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 3 issues
 * Retry Count   : 0
 *
 * === Description ===
 * This vulnerability exploits timestamp dependence in a multi-transaction sequence. An attacker (miner) can manipulate block timestamps to bypass the extension cooldown mechanism. The vulnerability requires: 1) First calling requestExtension() 2) Waiting for the required time period 3) Calling extendCrowdsaleWindow() with manipulated timestamps. The miner can manipulate the 'now' timestamp to make it appear that 24+ hours have passed since the last extension, resetting the extension counter and allowing unlimited extensions during critical crowdsale periods.
 */
pragma solidity ^0.4.16;

interface Token {
    function transfer(address _to, uint256 _value) public;
}

contract BXXCrowdsale {
    
    Token public tokenReward;
    address public creator;
    address public owner = 0x54aEe5794e0e012775D9E3E86Eb6a7edf0e0380F;

    uint256 public price;
    uint256 public startDate;
    uint256 public endDate;

    // === FALLBACK INJECTION: Timestamp Dependence ===
    // This function was added as a fallback when existing functions failed injection
    uint256 public extensionCount = 0;
    uint256 public lastExtensionTime = 0;
    mapping(address => uint256) public extensionRequests;

    function requestExtension() public {
        require(msg.sender == creator || msg.sender == owner);
        extensionRequests[msg.sender] = now;
    }

    modifier isCreator() {
        require(msg.sender == creator);
        _;
    }

    function extendCrowdsaleWindow(uint256 _additionalDays) isCreator public {
        require(_additionalDays <= 30);
        require(now > endDate - 86400); // Only allow extension in last 24 hours
        require(extensionRequests[msg.sender] > 0);
        require(now - extensionRequests[msg.sender] >= 3600); // Must wait 1 hour after request
        
        // Vulnerability: Using block.timestamp (now) for critical business logic
        if (now - lastExtensionTime > 86400) { // If more than 24 hours since last extension
            extensionCount = 0; // Reset counter
        }
        
        require(extensionCount < 3); // Max 3 extensions per 24-hour period
        
        endDate = endDate + (_additionalDays * 86400);
        lastExtensionTime = now;
        extensionCount++;
        
        // Clear the extension request
        extensionRequests[msg.sender] = 0;
    }
    // === END FALLBACK INJECTION ===

    event FundTransfer(address backer, uint amount, bool isContribution);

    function BXXCrowdsale() public {
        creator = msg.sender;
        startDate = 1518393600;
        endDate = 1523142000;
        price = 5000;
        tokenReward = Token(0x53562419E435cBAe65d73E7EAe2723A43E6cd887);
    }

    function setOwner(address _owner) isCreator public {
        owner = _owner;      
    }

    function setCreator(address _creator) isCreator public {
        creator = _creator;      
    }

    function setStartDate(uint256 _startDate) isCreator public {
        startDate = _startDate;      
    }

    function setEndtDate(uint256 _endDate) isCreator public {
        endDate = _endDate;      
    }

    function setPrice(uint256 _price) isCreator public {
        price = _price;      
    }

    function setToken(address _token) isCreator public {
        tokenReward = Token(_token);      
    }

    function sendToken(address _to, uint256 _value) isCreator public {
        tokenReward.transfer(_to, _value);      
    }

    function () payable public {
        require(msg.value > 0);
        require(now > startDate);
        require(now < endDate);
	    uint amount = msg.value * price;
        tokenReward.transfer(msg.sender, amount);
        FundTransfer(msg.sender, amount, true);
        owner.transfer(msg.value);
    }
}
