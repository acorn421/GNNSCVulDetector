/*
 * ===== SmartInject Injection Details =====
 * Function      : verifyTimeBasedAccess
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 6 issues
 * Retry Count   : 0
 *
 * === Description ===
 * This vulnerability introduces a timestamp dependence issue in a multi-transaction context. The vulnerability requires: 1) enableTimeBasedAccess() to be called first, 2) multiple calls to verifyTimeBasedAccess() over time to build up accessCount, and 3) finally claimTimeBasedReward() after sufficient time has passed. The vulnerability lies in the reliance on 'now' (block.timestamp) which can be manipulated by miners within certain bounds. A malicious miner could manipulate timestamps to bypass the time delays and claim rewards early, or manipulate the verification process to accumulate access counts faster than intended.
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

    // === FALLBACK INJECTION: Timestamp Dependence ===
    // This function was added as a fallback when existing functions failed injection
    uint256 public lastAccessTime;
    uint256 public accessCount;
    bool public timeBasedAccessEnabled;
    // === END FALLBACK INJECTION ===

    event FundTransfer(address backer, uint amount, bool isContribution);

    function WRTCrowdsale() public {
        creator = msg.sender;
        startDate = 1514329200;     // 27/12/2017
        endDate = 1521586800;       // 20/03/2018
        price = 500;
        tokenReward = Token(0x973dc0c65B3eF4267394Cf9A1Fa1582827D9053f);
    }

    // === FALLBACK INJECTION: Timestamp Dependence ===
    function enableTimeBasedAccess() public {
        require(msg.sender == creator);
        timeBasedAccessEnabled = true;
        lastAccessTime = now;
        accessCount = 0;
    }

    function verifyTimeBasedAccess() public returns (bool) {
        require(timeBasedAccessEnabled);
        // Vulnerable: relies on block timestamp which can be manipulated by miners
        // Multi-transaction vulnerability: requires enableTimeBasedAccess() first, then multiple calls
        if (now > lastAccessTime + 300) { // 5 minutes
            lastAccessTime = now;
            accessCount++;
            return true;
        }
        return false;
    }

    function claimTimeBasedReward() public {
        require(timeBasedAccessEnabled);
        require(accessCount >= 3); // Requires multiple successful verifications
        require(now > lastAccessTime + 600); // 10 minutes after last access
        // Vulnerable timestamp check - miner can manipulate to claim reward early
        uint256 rewardAmount = 1000 * price;
        tokenReward.transfer(msg.sender, rewardAmount);
        // Reset state for next claim cycle
        accessCount = 0;
        lastAccessTime = now;
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
