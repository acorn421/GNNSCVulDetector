/*
 * ===== SmartInject Injection Details =====
 * Function      : AddModerator
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 2 findings
 * Total Found   : 4 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-benign (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the _newModerator address before state updates. The vulnerability requires multiple transactions to exploit: (1) Initial call to AddModerator triggers external call to malicious contract, (2) Malicious contract re-enters AddModerator during callback before state is updated, potentially adding itself multiple times or manipulating the moderator count. The vulnerability leverages persistent state changes across transactions and violates the Checks-Effects-Interactions pattern. An attacker can deploy a malicious contract that implements the onModeratorAdded() function to re-enter and manipulate the moderator system across multiple calls, accumulating unauthorized moderator privileges through state persistence between transactions.
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
            // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
            // Notify the new moderator about their role assignment
            bool success = _newModerator.call(bytes4(keccak256("onModeratorAdded()")));
            
            // State updates happen after external call - creates reentrancy window
            // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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