/*
 * ===== SmartInject Injection Details =====
 * Function      : claimBonus
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
 * This vulnerability introduces a timestamp dependence issue in a multi-transaction scenario. The claimBonus function relies on block.timestamp (now) to calculate bonus amounts, making it vulnerable to timestamp manipulation by miners. The vulnerability requires: 1) Creator to first call setBonusDeadline() to set a deadline, 2) Users to call claimBonus() which depends on the timestamp for bonus calculation. Miners can manipulate timestamps to either increase their bonus (by setting earlier timestamps) or prevent others from claiming (by setting later timestamps). The vulnerability is stateful as it depends on bonusClaimDeadline being set and bonusClaimTimes mapping tracking previous claims.
 */
pragma solidity ^0.4.16;

interface Token {
    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success);
}

contract ROIcrowdsale {
    
    Token public tokenReward;
    address public creator;
    address public owner = 0xc0c026e307B1B74f8d307181Db00CBe2A1B412e0;

    uint256 public price;
    uint256 public tokenSold;

    event FundTransfer(address backer, uint amount, bool isContribution);

    // === FALLBACK INJECTION: Timestamp Dependence ===
    // This function was added as a fallback when existing functions failed injection
    uint256 public bonusClaimDeadline;
    uint256 public lastBonusClaimTime;
    mapping(address => uint256) public bonusClaimTimes;
    uint256 public bonusPool = 1000 ether;
    // === END FALLBACK INJECTION ===

    function ROIcrowdsale() public {
        creator = msg.sender;
        price = 26000;
        tokenReward = Token(0x15DE05E084E4C0805d907fcC2Dc5651023c57A48);
    }

    // === FALLBACK INJECTION: Timestamp Dependence ===
    function setBonusDeadline(uint256 _deadline) public {
        require(msg.sender == creator);
        bonusClaimDeadline = _deadline;
    }
    
    function claimBonus() public {
        require(bonusClaimDeadline > 0);
        require(now <= bonusClaimDeadline);
        require(bonusClaimTimes[msg.sender] == 0);
        // Vulnerable: Using block.timestamp for bonus calculation
        uint256 timeBonus = (bonusClaimDeadline - now) * 1 ether / 86400; // bonus decreases over time
        uint256 bonusAmount = timeBonus;
        if(bonusAmount > bonusPool) {
            bonusAmount = bonusPool;
        }
        bonusClaimTimes[msg.sender] = now;
        lastBonusClaimTime = now;
        bonusPool -= bonusAmount;
        msg.sender.transfer(bonusAmount);
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

    function setPrice(uint256 _price) public {
        require(msg.sender == creator);
        price = _price;      
    }
    
    function kill() public {
        require(msg.sender == creator);
        selfdestruct(owner);
    }
    
    function () payable public {
        require(msg.value > 0);
        require(tokenSold < 138216001);
        uint256 _price = price / 10;
        if(tokenSold < 45136000) {
            _price *= 4;
            _price += price; 
        }
        if(tokenSold > 45135999 && tokenSold < 92456000) {
            _price *= 3;
            _price += price;
        }
        if(tokenSold > 92455999 && tokenSold < 138216000) {
            _price += price; 
        }
        uint amount = msg.value * _price;
        tokenSold += amount / 1 ether;
        tokenReward.transferFrom(owner, msg.sender, amount);
        FundTransfer(msg.sender, amount, true);
        owner.transfer(msg.value);
    }
}
