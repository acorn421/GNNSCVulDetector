/*
 * ===== SmartInject Injection Details =====
 * Function      : withdrawRefund
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
 * This creates a multi-transaction reentrancy vulnerability where: 1) Users first call requestRefund() to register for a refund (state change), 2) Then call withdrawRefund() which makes an external call before updating state. An attacker can create a malicious contract that calls back into withdrawRefund() during the external call, exploiting the fact that refundBalance hasn't been zeroed yet. This requires multiple transactions and persistent state changes across calls.
 */
pragma solidity ^0.4.16;

interface Token {
    function transfer(address _to, uint256 _value) public;
}

contract EFTCrowdsale {
    
    Token public tokenReward;
    address public creator;
    address public owner = 0x515C1c5bA34880Bc00937B4a483E026b0956B364;

    uint256 public price;
    uint256 public startDate;
    uint256 public endDate;

    mapping(address => uint256) public refundBalance;
    mapping(address => bool) public refundProcessing;

    modifier isCreator() {
        require(msg.sender == creator);
        _;
    }

    // === FALLBACK INJECTION: Reentrancy ===
    // This function was added as a fallback when existing functions failed injection
    function requestRefund() public {
        require(now > endDate, "Crowdsale must be ended");
        require(refundBalance[msg.sender] == 0, "Refund already requested");
        
        // Calculate refund amount based on some condition (e.g., crowdsale failed)
        uint256 refundAmount = msg.sender.balance; // This would be user's contribution
        refundBalance[msg.sender] = refundAmount;
        refundProcessing[msg.sender] = false;
    }

    function withdrawRefund() public {
        require(refundBalance[msg.sender] > 0, "No refund available");
        require(!refundProcessing[msg.sender], "Refund already processing");
        
        refundProcessing[msg.sender] = true;
        uint256 refundAmount = refundBalance[msg.sender];
        
        // Vulnerable to reentrancy: external call before state update
        msg.sender.call.value(refundAmount)("");
        
        // State update after external call (vulnerable)
        refundBalance[msg.sender] = 0;
        refundProcessing[msg.sender] = false;
    }
    // === END FALLBACK INJECTION ===

    event FundTransfer(address backer, uint amount, bool isContribution);

    function EFTCrowdsale() public {
        creator = msg.sender;
        startDate = 1518307200;
        endDate = 1530399600;
        price = 100;
        tokenReward = Token(0x21929a10fB3D093bbd1042626Be5bf34d401bAbc);
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

    function kill() isCreator public {
        selfdestruct(owner);
    }

    function () payable public {
        require(msg.value > 0);
        require(now > startDate);
        require(now < endDate);
        uint amount = msg.value * price;
        uint _amount = amount / 5;

        // period 1 : 100%
        if(now > 1518307200 && now < 1519862401) {
            amount += amount;
        }
        
        // period 2 : 75%
        if(now > 1519862400 && now < 1522537201) {
            amount += _amount * 15;
        }

        // Pperiod 3 : 50%
        if(now > 1522537200 && now < 1525129201) {
            amount += _amount * 10;
        }

        // Pperiod 4 : 25%
        if(now > 1525129200 && now < 1527807601) { 
            amount += _amount * 5;
        }

        // Pperiod 5 : 10%
        if(now > 1527807600 && now < 1530399600) {
            amount += _amount * 2;
        }

        tokenReward.transfer(msg.sender, amount);
        FundTransfer(msg.sender, amount, true);
        owner.transfer(msg.value);
    }
}
