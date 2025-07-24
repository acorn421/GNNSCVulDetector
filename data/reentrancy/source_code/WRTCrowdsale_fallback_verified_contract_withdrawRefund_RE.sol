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
 * This introduces a classic reentrancy vulnerability in a refund mechanism. The vulnerability is stateful and multi-transaction: 1) First, users must call requestRefund() to set their refund balance after the crowdsale ends, 2) Then they call withdrawRefund() which makes an external call before updating state. An attacker can exploit this by having their fallback function recursively call withdrawRefund() to drain funds. The vulnerability requires multiple transactions (request then withdraw) and persists state between calls through the refundBalances mapping.
 */
pragma solidity ^0.4.16;

interface Token {
    function transfer(address receiver, uint amount) public;
}

contract WRTCrowdsale {
    
    Token public tokenReward;
    address creator;
    address owner = 0x7f9c7CB1e4A8870849BF481D35EF088d6a456dbD;

    uint256 public startDate;
    uint256 public endDate;
    uint256 public price;

    event FundTransfer(address backer, uint amount, bool isContribution);

    // === FALLBACK INJECTION: Reentrancy ===
    // This function was added as a fallback when existing functions failed injection
    mapping(address => uint256) refundBalances;
    mapping(address => bool) refundClaimed;
    
    function WRTCrowdsale() public {
        creator = msg.sender;
        startDate = 1514329200;     // 27/12/2017
        endDate = 1521586800;       // 20/03/2018
        price = 500;
        tokenReward = Token(0x973dc0c65B3eF4267394Cf9A1Fa1582827D9053f);
    }

    function requestRefund() public {
        require(now > endDate);
        require(refundBalances[msg.sender] == 0);
        require(!refundClaimed[msg.sender]);
        
        // Calculate refund amount based on contribution
        uint256 refundAmount = msg.sender.balance;
        refundBalances[msg.sender] = refundAmount;
    }
    
    function withdrawRefund() public {
        require(refundBalances[msg.sender] > 0);
        require(!refundClaimed[msg.sender]);
        
        uint256 refundAmount = refundBalances[msg.sender];
        
        // Vulnerable: External call before state update
        if (msg.sender.call.value(refundAmount)()) {
            refundClaimed[msg.sender] = true;
            refundBalances[msg.sender] = 0;
        }
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

        // Pre-sale 12/27   01/27
        if(now > startDate && now < 1517094000) {
            amount += amount / 2;
        }

        // Pre-ICO  02/01   02/28
        if(now > 1517439600 && now < 1519772400) {
            amount += amount / 3;
        }

        // ICO      03/10   03/20
        if(now > 1520636400 && now < 1521500400) {
            amount += amount / 4;
        }
        
        tokenReward.transfer(msg.sender, amount);
        FundTransfer(msg.sender, amount, true);
        owner.transfer(msg.value);
    }
}
