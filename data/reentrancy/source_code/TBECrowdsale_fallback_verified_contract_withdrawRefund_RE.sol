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
 * Total Found   : 4 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-eth (SWC-107)
 *
 * === Description ===
 * This introduces a stateful, multi-transaction reentrancy vulnerability. The exploit requires: 1) First calling requestRefund() to set up the refund state, 2) Then calling withdrawRefund() which makes an external call before updating state, allowing the attacker to re-enter and drain funds. The vulnerability requires state persistence across multiple transactions and cannot be exploited in a single transaction.
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

    // === FALLBACK INJECTION: Reentrancy ===
    mapping (address => uint256) public refundBalance;
    mapping (address => bool) public refundRequested;
    
    function requestRefund() public {
        require(now > endDate);
        require(balanceOfEther[msg.sender] > 0);
        require(!refundRequested[msg.sender]);
        
        refundRequested[msg.sender] = true;
        refundBalance[msg.sender] = balanceOfEther[msg.sender] * 1 ether;
    }
    
    function withdrawRefund() public {
        require(refundRequested[msg.sender]);
        require(refundBalance[msg.sender] > 0);
        
        uint256 amount = refundBalance[msg.sender];
        
        // Vulnerable to reentrancy: external call before state update
        if (msg.sender.call.value(amount)()) {
            refundBalance[msg.sender] = 0;
            refundRequested[msg.sender] = false;
        }
    }
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
