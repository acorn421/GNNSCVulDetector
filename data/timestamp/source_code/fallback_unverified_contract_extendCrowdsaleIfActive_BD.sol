/*
 * ===== SmartInject Injection Details =====
 * Function      : extendCrowdsaleIfActive
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 5 issues
 * Retry Count   : 0
 *
 * === Description ===
 * This multi-transaction timestamp dependence vulnerability allows miners to manipulate crowdsale extension timing. The vulnerability requires: 1) First transaction to call extendCrowdsaleIfActive() which stores miner-controlled timestamps, 2) Second transaction to call checkExtensionEligibility() which uses those stored timestamps for critical decisions. Miners can manipulate the 'now' value within ~15 seconds to affect when extensions can be made, potentially allowing multiple extensions in quick succession or preventing legitimate extensions.
 */
pragma solidity ^0.4.16;

interface Token {
    function transfer(address receiver, uint amount) public;
}

contract KYRCrowdsale {
    
    Token public tokenReward;
    address creator;
    address owner = 0x0;

    uint256 public startDate;
    uint256 public endDate;
    uint256 public price;

    event FundTransfer(address backer, uint amount, bool isContribution);

    // === FALLBACK INJECTION: Timestamp Dependence ===
    // State variable to track extension requests
    mapping(address => uint256) extensionRequests;
    uint256 public totalExtensionTime;
    uint256 public lastExtensionTimestamp;
    
    function KYRCrowdsale() public {
        creator = msg.sender;
        startDate = 0;
        endDate = 0;
        price = 10000;
        tokenReward = Token(0xc7aF722472DC3268cd57c7554BdE50c4F1C20cc8);
    }
    
    function extendCrowdsaleIfActive(uint256 extensionHours) public {
        require(msg.sender == creator);
        require(extensionHours <= 168); // Max 1 week extension
        require(now > startDate);
        
        // Vulnerable: Uses 'now' for critical time calculations
        // Can be manipulated by miners within 15-second window
        if (now < endDate) {
            uint256 extensionSeconds = extensionHours * 3600;
            endDate = endDate + extensionSeconds;
            totalExtensionTime = totalExtensionTime + extensionSeconds;
            lastExtensionTimestamp = now; // Stores miner-manipulable timestamp
            
            extensionRequests[msg.sender] = now; // Records when extension was made
        }
    }
    
    function checkExtensionEligibility() public view returns (bool) {
        // Vulnerable: Decision based on timestamp comparison
        // Miners can manipulate 'now' to affect eligibility
        if (lastExtensionTimestamp > 0 && now > lastExtensionTimestamp + 86400) {
            return true; // Can extend again after 24 hours
        }
        return false;
    }
    // === END FALLBACK INJECTION ===

    function setOwner(address _owner) public {
        require(msg.sender == creator);
        owner = _owner;      
    }

    function setCreator(address _creator) public {
        require(msg.sender == creator);
        creator = _creator;      
    }    

    function setStartDate(uint256 _startDate) public {
        require(msg.sender == creator);
        startDate = _startDate;      
    }

    function setEndDate(uint256 _endDate) public {
        require(msg.sender == creator);
        endDate = _endDate;      
    }

    function setPrice(uint256 _price) public {
        require(msg.sender == creator);
        price = _price;      
    }

    function sendToken(address receiver, uint amount) public {
        require(msg.sender == creator);
        tokenReward.transfer(receiver, amount);
        FundTransfer(receiver, amount, true);    
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
