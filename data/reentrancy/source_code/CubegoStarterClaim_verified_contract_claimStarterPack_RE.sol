/*
 * ===== SmartInject Injection Details =====
 * Function      : claimStarterPack
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 2 findings
 * Total Found   : 2 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-benign (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by creating a temporary state manipulation pattern. The vulnerability works by:
 * 
 * 1. **State Manipulation Pattern**: The function temporarily sets `_claimed[msg.sender] = true`, then resets it to `false` after the external call, before setting it back to `true`. This creates a reentrancy window where the claim status is inconsistent.
 * 
 * 2. **Multi-Transaction Exploitation**: 
 *    - **Transaction 1**: Attacker calls `claimStarterPack()` with a malicious contract as the recipient
 *    - **Transaction 2**: The malicious contract's `mineMaterial` callback function can reenter the same or other functions during the window where `_claimed[msg.sender] = false`
 *    - **Transaction 3+**: Additional state manipulation can occur across multiple callback transactions
 * 
 * 3. **Stateful Vulnerability**: The exploit relies on the persistent state changes between transactions. The temporary state reset creates a window where:
 *    - The initial claim check passes
 *    - The state is temporarily reset during external call
 *    - Reentrant calls can exploit this inconsistent state
 *    - Multiple transactions can accumulate invalid state changes
 * 
 * 4. **Cross-Function Reentrancy**: While the external call is executing, other functions that read `_claimed` status could be exploited, as the state is temporarily inconsistent.
 * 
 * 5. **Realistic Pattern**: This mimics real-world vulnerabilities where developers attempt to prevent reentrancy with temporary state changes but create larger attack surfaces.
 * 
 * The vulnerability requires multiple transactions because:
 * - The initial call establishes the attack context
 * - The reentrant callback occurs in a separate transaction context
 * - State accumulation happens across multiple callback transactions
 * - The exploit depends on the interleaving of multiple transaction executions
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
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Temporarily mark as claimed to prevent immediate double-claiming
        _claimed[msg.sender] = true;
        
        // External call that can reenter - vulnerability injection point
        cubegoCore.mineMaterial(msg.sender, mId, mAmount);
        
        // Reset claim status if external call succeeds (creates reentrancy window)
        _claimed[msg.sender] = false;
        
        // Final state update after external call
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        _claimed[msg.sender] = true;
        claimedCount += 1;
        return true;
    }
}