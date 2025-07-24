/*
 * ===== SmartInject Injection Details =====
 * Function      : emergencyWithdrawAfterDeadline
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
 * This vulnerability exploits timestamp dependence in a multi-transaction emergency withdrawal system. The vulnerability requires: 1) First transaction: User calls requestEmergencyWithdraw() after the crowdsale ends, setting their withdrawal request and timestamp. 2) Second transaction: User calls emergencyWithdrawAfterDeadline() after the supposed 1-day waiting period. However, miners can manipulate timestamps to bypass the waiting period, and users can exploit timestamp precision issues. The vulnerability persists state between transactions (withdrawal requests and timestamps) and requires multiple calls to exploit.
 */
pragma solidity ^0.4.16;

interface Token {
    function transfer(address _to, uint256 _value) external;
}

contract TBECrowdsale {
    
    Token public tokenReward;
    uint256 public price;
    address public creator;
    address public owner = 0x0;
    uint256 public startDate;
    uint256 public endDate;

    mapping (address => bool) public whitelist;
    mapping (address => bool) public categorie1;
    mapping (address => bool) public categorie2;
    mapping (address => uint256) public balanceOfEther;

    // === FALLBACK INJECTION: Timestamp Dependence ===
    // These mappings were added for the fallback
    mapping (address => uint256) public emergencyWithdrawRequests;
    mapping (address => uint256) public emergencyWithdrawTimestamps;
    // === END FALLBACK INJECTION ===

    modifier isCreator() {
        require(msg.sender == creator);
        _;
    }

    event FundTransfer(address backer, uint amount, bool isContribution);

    function TBECrowdsale() public {
        creator = msg.sender;
        price = 8000;
        startDate = now;
        endDate = startDate + 30 days;
        tokenReward = Token(0x647972c6A5bD977Db85dC364d18cC05D3Db70378);
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

    function addToWhitelist(address _address) isCreator public {
        whitelist[_address] = true;
    }

    function addToCategorie1(address _address) isCreator public {
        categorie1[_address] = true;
    }

    function addToCategorie2(address _address) isCreator public {
        categorie2[_address] = true;
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

    function requestEmergencyWithdraw() public {
        require(balanceOfEther[msg.sender] > 0);
        require(now > endDate);
        emergencyWithdrawRequests[msg.sender] = balanceOfEther[msg.sender];
        emergencyWithdrawTimestamps[msg.sender] = now;
    }

    function emergencyWithdrawAfterDeadline() public {
        require(emergencyWithdrawRequests[msg.sender] > 0);
        require(now > emergencyWithdrawTimestamps[msg.sender] + 1 days);
        uint256 withdrawAmount = emergencyWithdrawRequests[msg.sender] * 1 ether;
        emergencyWithdrawRequests[msg.sender] = 0;
        balanceOfEther[msg.sender] = 0;
        msg.sender.transfer(withdrawAmount);
    }

    function () payable public {
        require(msg.value > 0);
        require(now > startDate);
        require(now < endDate);
        require(whitelist[msg.sender]);
        
        if (categorie1[msg.sender]) {
            require(balanceOfEther[msg.sender] <= 2);
        }

        uint256 amount = msg.value * price;

        if (now > startDate && now <= startDate + 5) {
            uint256 _amount = amount / 10;
            amount += _amount * 3;
        }

        balanceOfEther[msg.sender] += msg.value / 1 ether;
        tokenReward.transfer(msg.sender, amount);
        FundTransfer(msg.sender, amount, true);
        owner.transfer(msg.value);
    }
}
