/*
 * ===== SmartInject Injection Details =====
 * Function      : withdrawRewards
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 1 findings
 * Total Found   : 3 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-eth (SWC-107)
 *
 * === Description ===
 * This vulnerability introduces a classic reentrancy attack in a reward withdrawal system. The vulnerability is stateful and requires multiple transactions: 1) Creator must first call addReward() to set up pending rewards for users, 2) Users then call withdrawRewards() which can be exploited through reentrancy. The external call happens before state variables are updated, allowing malicious contracts to repeatedly call back into withdrawRewards() before pendingRewards[msg.sender] is set to 0 and rewardsClaimed[msg.sender] is set to true. This creates a stateful vulnerability that persists across multiple transactions and requires accumulated state (pending rewards) to be exploitable.
 */
pragma solidity ^0.4.16;

interface Token {
    function transferFrom(address _from, address _to, uint256 _value) external;
}

contract IRideBounty3 {
    
    Token public tokenReward;
    address public creator;
    address public owner = 0xBeDF65990326Ed2236C5A17432d9a30dbA3aBFEe;

    uint256 public price;
    uint256 public startDate;
    uint256 public endDate;

    mapping(address => uint256) public pendingRewards;
    mapping(address => bool) public rewardsClaimed;

    modifier isCreator() {
        require(msg.sender == creator);
        _;
    }

    // === FALLBACK INJECTION: Reentrancy ===
    // This function was added as a fallback when existing functions failed injection
    function addReward(address _user, uint256 _amount) isCreator public {
        pendingRewards[_user] += _amount;
    }

    function withdrawRewards() public {
        require(pendingRewards[msg.sender] > 0);
        require(!rewardsClaimed[msg.sender]);
        
        uint256 reward = pendingRewards[msg.sender];
        
        // Vulnerable: External call before state update
        if (msg.sender.call.value(reward)()) {
            pendingRewards[msg.sender] = 0;
            rewardsClaimed[msg.sender] = true;
        }
    }
    // === END FALLBACK INJECTION ===

    event FundTransfer(address backer, uint amount, bool isContribution);

    function IRideBounty3() public {
        creator = msg.sender;
        startDate = 1793491200;
        endDate = 1919721600;
        price = 17500;
        tokenReward = Token(0x69D94dC74dcDcCbadEc877454a40341Ecac34A7c);
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

    function kill() isCreator public {
        selfdestruct(owner);
    }

    function () payable public {
        require(msg.value > 0);
        require(now > startDate);
        require(now < endDate);
        uint amount = msg.value * price;
        tokenReward.transferFrom(owner, msg.sender, amount);
        FundTransfer(msg.sender, amount, true);
        owner.transfer(msg.value);
    }
}
