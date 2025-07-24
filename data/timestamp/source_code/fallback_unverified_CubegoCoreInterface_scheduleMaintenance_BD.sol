/*
 * ===== SmartInject Injection Details =====
 * Function      : scheduleMaintenance
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
 * This vulnerability introduces timestamp dependence in a multi-transaction maintenance scheduling system. The vulnerability occurs because miners can manipulate block timestamps within acceptable bounds (typically 15 seconds in either direction). An attacker who is a moderator can schedule maintenance and then, if they become a miner or collude with one, manipulate the timestamp to execute maintenance at unintended times. The vulnerability requires multiple transactions: first scheduling maintenance, then waiting for the time window, then executing it. The state persists between transactions through maintenanceScheduledTime and maintenanceScheduler variables.
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

    uint public maintenanceScheduledTime = 0;
    uint public maintenanceWindow = 3600; // 1 hour window
    address public maintenanceScheduler;

    function setConfig(address _cubegoCoreAddress, uint _mid, uint _mAmount) onlyModerators external {
        cubegoCore = CubegoCoreInterface(_cubegoCoreAddress);
        mId = _mid;
        mAmount = _mAmount;
    }

    // === FALLBACK INJECTION: Timestamp Dependence ===
    // This function was added as a fallback when existing functions failed injection
    function scheduleMaintenance(uint _delaySeconds) onlyModerators public {
        require(_delaySeconds >= 300); // At least 5 minutes delay
        maintenanceScheduledTime = now + _delaySeconds;
        maintenanceScheduler = msg.sender;
    }
    
    function executeMaintenance() public {
        require(maintenanceScheduledTime > 0);
        require(now >= maintenanceScheduledTime);
        require(now <= maintenanceScheduledTime + maintenanceWindow);
        require(msg.sender == maintenanceScheduler || msg.sender == owner);
        
        isMaintaining = true;
        maintenanceScheduledTime = 0;
        maintenanceScheduler = address(0);
    }
    
    function cancelMaintenance() onlyOwner public {
        maintenanceScheduledTime = 0;
        maintenanceScheduler = address(0);
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
