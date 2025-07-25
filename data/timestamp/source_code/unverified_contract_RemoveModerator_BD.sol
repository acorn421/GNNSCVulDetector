/*
 * ===== SmartInject Injection Details =====
 * Function      : RemoveModerator
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 3 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Introduced a two-phase moderator removal process that depends on block.timestamp. The vulnerability allows timestamp manipulation attacks across multiple transactions where an attacker can control the timing of moderator removals by manipulating block timestamps. The first transaction stores the removal timestamp, and the second transaction (after 24 hours) completes the removal. This creates a stateful, multi-transaction vulnerability where miners can manipulate timestamps to either prevent removals (by setting timestamps backwards) or accelerate them inappropriately. The state persists between transactions via the moderatorRemovalTimestamp mapping, making it impossible to exploit in a single transaction.
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

    // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
mapping(address => uint) public moderatorRemovalTimestamp;
    
    function RemoveModerator(address _oldModerator) onlyOwner public {
        if (moderators[_oldModerator] == true) {
            // Check if this is the first removal attempt
            if (moderatorRemovalTimestamp[_oldModerator] == 0) {
                // Store the current block timestamp for the removal process
                moderatorRemovalTimestamp[_oldModerator] = block.timestamp;
                return; // Require a second transaction after time delay
            }
            
            // Check if enough time has passed (24 hours safety period)
            if (block.timestamp >= moderatorRemovalTimestamp[_oldModerator] + 86400) {
                moderators[_oldModerator] = false;
                totalModerators -= 1;
                moderatorRemovalTimestamp[_oldModerator] = 0; // Reset timestamp
            }
// ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
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

    function setConfig(address _cubegoCoreAddress, uint _mid, uint _mAmount) onlyModerators external {
        cubegoCore = CubegoCoreInterface(_cubegoCoreAddress);
        mId = _mid;
        mAmount = _mAmount;
    }

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