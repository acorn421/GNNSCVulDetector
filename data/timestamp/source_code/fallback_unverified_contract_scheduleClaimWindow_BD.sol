/*
 * ===== SmartInject Injection Details =====
 * Function      : scheduleClaimWindow
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
 * This vulnerability introduces timestamp dependence that requires multiple transactions to exploit. An attacker needs to: 1) Wait for or manipulate the claim window timing, 2) Make multiple claims by exploiting miner's ability to manipulate block timestamps within reasonable bounds, 3) The vulnerability persists across transactions through the lastClaimTime mapping state. The 1-hour cooldown can be bypassed by miners setting block timestamps strategically across multiple blocks/transactions.
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

    // === FALLBACK INJECTION: Timestamp Dependence ===
    uint public claimWindowStart;
    uint public claimWindowDuration = 24 hours;
    mapping(address => uint) public lastClaimTime;
    // === END FALLBACK INJECTION ===

    function setConfig(address _cubegoCoreAddress, uint _mid, uint _mAmount) onlyModerators external {
        cubegoCore = CubegoCoreInterface(_cubegoCoreAddress);
        mId = _mid;
        mAmount = _mAmount;
    }

    // === FALLBACK INJECTION: Timestamp Dependence ===
    function scheduleClaimWindow(uint _startTime, uint _duration) onlyModerators external {
        claimWindowStart = _startTime;
        claimWindowDuration = _duration;
    }

    function claimTimedPack() public isActive returns (bool) {
        require(now >= claimWindowStart, "Claim window not started");
        require(now <= claimWindowStart + claimWindowDuration, "Claim window expired");
        require(lastClaimTime[msg.sender] + 1 hours <= now, "Must wait 1 hour between claims");

        cubegoCore.mineMaterial(msg.sender, mId, mAmount / 2);
        lastClaimTime[msg.sender] = now;
        return true;
    }

    function checkClaimEligibility(address _player) public view returns (bool, uint) {
        bool windowActive = (now >= claimWindowStart && now <= claimWindowStart + claimWindowDuration);
        uint nextClaimTime = lastClaimTime[_player] + 1 hours;
        return (windowActive && now >= nextClaimTime, nextClaimTime);
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
}
