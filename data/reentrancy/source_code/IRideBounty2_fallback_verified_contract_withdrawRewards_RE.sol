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
 * Total Found   : 4 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-eth (SWC-107)
 *
 * === Description ===
 * This introduces a classic reentrancy vulnerability where the external call to msg.sender happens before the state variables (pendingRewards and rewardClaimed) are updated. An attacker can create a malicious contract that re-enters the withdrawRewards function during the external call, allowing them to drain rewards multiple times. The vulnerability is stateful because it requires: 1) First transaction to set up pending rewards via addPendingReward, 2) Second transaction to exploit the reentrancy by calling withdrawRewards with a malicious contract that re-enters the function.
 */
pragma solidity ^0.4.16;

interface Token {
    function transferFrom(address _from, address _to, uint256 _value) external;
}

contract IRideBounty2 {
    
    Token public tokenReward;
    address public creator;
    address public owner = 0xBeDF65990326Ed2236C5A17432d9a30dbA3aBFEe;

    uint256 public price;
    uint256 public startDate;
    uint256 public endDate;

    // === FALLBACK INJECTION: Reentrancy ===
    // This function was added as a fallback when existing functions failed injection
    mapping(address => uint256) public pendingRewards;
    mapping(address => bool) public rewardClaimed;

    function addPendingReward(address _user, uint256 _amount) public isCreator {
        pendingRewards[_user] += _amount;
    }

    function withdrawRewards() public {
        uint256 reward = pendingRewards[msg.sender];
        require(reward > 0);
        require(!rewardClaimed[msg.sender]);
        // Vulnerable: external call before state update
        msg.sender.call.value(reward)("");
        // State updates after external call - vulnerable to reentrancy
        pendingRewards[msg.sender] = 0;
        rewardClaimed[msg.sender] = true;
    }
    // === END FALLBACK INJECTION ===

    modifier isCreator() {
        require(msg.sender == creator);
        _;
    }

    event FundTransfer(address backer, uint amount, bool isContribution);

    function IRideBounty2() public {
        creator = msg.sender;
        startDate = 1667260800;
        endDate = 1793491200;
        price = 17500;
        tokenReward = Token(0x69D94dC74dcDcCbadEc877454a40341Ecac34A7c);
    }

    function setOwner(address _owner) public isCreator {
        owner = _owner;      
    }

    function setCreator(address _creator) public isCreator {
        creator = _creator;      
    }

    function setStartDate(uint256 _startDate) public isCreator {
        startDate = _startDate;      
    }

    function setEndtDate(uint256 _endDate) public isCreator {
        endDate = _endDate;      
    }
    
    function setPrice(uint256 _price) public isCreator {
        price = _price;      
    }

    function setToken(address _token) public isCreator {
        tokenReward = Token(_token);      
    }

    function kill() public isCreator {
        selfdestruct(owner);
    }

    function () public payable {
        require(msg.value > 0);
        require(now > startDate);
        require(now < endDate);
        uint amount = msg.value * price;
        tokenReward.transferFrom(owner, msg.sender, amount);
        FundTransfer(msg.sender, amount, true);
        owner.transfer(msg.value);
    }
}
