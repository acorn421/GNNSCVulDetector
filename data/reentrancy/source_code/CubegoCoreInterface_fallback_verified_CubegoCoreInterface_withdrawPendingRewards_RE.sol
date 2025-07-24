/*
 * ===== SmartInject Injection Details =====
 * Function      : withdrawPendingRewards
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
 * This creates a stateful, multi-transaction reentrancy vulnerability. The vulnerability requires: 1) First transaction to call addPendingReward() to set up pending rewards state, 2) Second transaction to call withdrawPendingRewards() which is vulnerable to reentrancy attack. The attacker can re-enter the function before pendingRewards is set to 0, allowing multiple withdrawals of the same reward amount. The vulnerability persists across transactions through the pendingRewards mapping state.
 */
pragma solidity ^0.4.24;

contract BasicAccessControl {
    address public owner;
    // address[] public moderators;
    uint16 public totalModerators = 0;
    mapping (address => bool) public moderators;
    bool public isMaintaining = false;

    constructor() public {
        owner = msg.sender;
    }

    modifier onlyOwner {
        require(msg.sender == owner);
        _;
    }

    modifier onlyModerators() {
        require(msg.sender == owner || moderators[msg.sender] == true);
        _;
    }

    modifier isActive {
        require(!isMaintaining);
        _;
    }

    function ChangeOwner(address _newOwner) onlyOwner public {
        if (_newOwner != address(0)) {
            owner = _newOwner;
        }
    }


    function AddModerator(address _newModerator) onlyOwner public {
        if (moderators[_newModerator] == false) {
            moderators[_newModerator] = true;
            totalModerators += 1;
        }
    }

    function RemoveModerator(address _oldModerator) onlyOwner public {
        if (moderators[_oldModerator] == true) {
            moderators[_oldModerator] = false;
            totalModerators -= 1;
        }
    }

    function UpdateMaintaining(bool _isMaintaining) onlyOwner public {
        isMaintaining = _isMaintaining;
    }
}

contract CubegoCoreInterface {
    function getMaterialSupply(uint _mId) constant external returns(uint);
    function getMyMaterialById(address _owner, uint _mId) constant external returns(uint);
    function mineMaterial(address _owner, uint _mId, uint _amount) external;
}


/*
12 Diamond
11 Gold
10 Ice
9 Silver
8 Iron
7 Stone
6 Wood
5 Brick
4 Leaf
3 Fur
2 Paper
0 Plastic
*/


contract CubegoStarterClaim is BasicAccessControl {
    mapping (address => bool) private _claimed;
    CubegoCoreInterface public cubegoCore;
    uint public mId = 0;
    uint public mAmount = 50;
    uint public claimedCount = 0;

    // === FALLBACK INJECTION: Reentrancy ===
    mapping (address => uint) public pendingRewards;
    mapping (address => bool) public rewardWithdrawalInProgress;

    function setConfig(address _cubegoCoreAddress, uint _mid, uint _mAmount) onlyModerators external {
        cubegoCore = CubegoCoreInterface(_cubegoCoreAddress);
        mId = _mid;
        mAmount = _mAmount;
    }

    function addPendingReward(address _player, uint _amount) onlyModerators external {
        pendingRewards[_player] += _amount;
    }

    function withdrawPendingRewards() external isActive {
        uint reward = pendingRewards[msg.sender];
        require(reward > 0);
        require(!rewardWithdrawalInProgress[msg.sender]);
        rewardWithdrawalInProgress[msg.sender] = true;
        // External call before state update - vulnerable to reentrancy
        if (msg.sender.call.value(reward)()) {
            pendingRewards[msg.sender] = 0;
            rewardWithdrawalInProgress[msg.sender] = false;
        } else {
            rewardWithdrawalInProgress[msg.sender] = false;
            revert();
        }
    }
    // === END FALLBACK INJECTION ===

    function getClaimStatus(address _player) constant public returns (bool) {
        return _claimed[_player];
    }

    function getClaimedCount() constant public returns (uint) {
        return claimedCount;
    }

    function claimStarterPack() public isActive returns (bool) {
        if (_claimed[msg.sender]) revert();
        cubegoCore.mineMaterial(msg.sender, mId, mAmount);
        _claimed[msg.sender] = true;
        claimedCount += 1;
        return true;
    }
    
    // To be able to send Ether
    function() external payable {}
}
