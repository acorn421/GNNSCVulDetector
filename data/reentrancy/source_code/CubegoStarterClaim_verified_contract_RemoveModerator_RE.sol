/*
 * ===== SmartInject Injection Details =====
 * Function      : RemoveModerator
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
 * Introduced stateful, multi-transaction reentrancy vulnerability by:
 * 
 * 1. **Added Pending State System**: Created `pendingModeratorRemovals` mapping and `removalQueue` array to track removal requests across transactions. This creates persistent state that exists between function calls.
 * 
 * 2. **External Call Before State Finalization**: Added external call to `ModeratorRegistryInterface(moderatorRegistry).notifyModeratorRemoval()` that occurs BEFORE the moderator is actually removed from the `moderators` mapping. This violates the Checks-Effects-Interactions pattern.
 * 
 * 3. **State Inconsistency Window**: During the external call, the moderator appears active in the `moderators` mapping but is marked for removal in `pendingModeratorRemovals`. This creates a window where the moderator can still perform actions while being in a "pending removal" state.
 * 
 * **Multi-Transaction Exploitation Pattern:**
 * 
 * **Transaction 1**: Owner calls `RemoveModerator(moderatorA)`
 * - `pendingModeratorRemovals[moderatorA] = true` 
 * - `removalQueue.push(moderatorA)`
 * - External call to `notifyModeratorRemoval(moderatorA)` occurs
 * - **During external call**: moderatorA is still active in `moderators` mapping
 * - **Reentrancy opportunity**: External contract can call back into functions that check moderator status
 * 
 * **Transaction 2**: Attacker exploits the state inconsistency
 * - While moderatorA is pending removal, they can still use moderator privileges
 * - Functions using `moderators[moderatorA]` will return `true`
 * - Attacker can perform privileged operations before removal is finalized
 * 
 * **Why Multi-Transaction is Required:**
 * 
 * 1. **Persistent State**: The `pendingModeratorRemovals` mapping and `removalQueue` persist between transactions, creating lasting state inconsistencies.
 * 
 * 2. **Asynchronous Removal Process**: The removal process is now split across multiple steps that can span transactions, unlike the original atomic operation.
 * 
 * 3. **External Dependency**: The external call to `ModeratorRegistryInterface` introduces a dependency that can fail or be manipulated across transactions.
 * 
 * 4. **State Accumulation**: Multiple removal requests can accumulate in the queue, each creating opportunities for exploitation in subsequent transactions.
 * 
 * The vulnerability requires multiple transactions because the exploit depends on the time window between marking a moderator for removal and actually removing them - a window that can persist across transaction boundaries and be exploited by subsequent calls.
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

    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
    mapping (address => bool) private pendingModeratorRemovals;
    address[] private removalQueue;
    address public moderatorRegistry;

    function setModeratorRegistry(address _registry) onlyOwner public {
        moderatorRegistry = _registry;
    }

    // Note: Removed misplaced 'interface' declaration. Instead, we'll just use the selector directly as already done in the low-level call.
    
    function RemoveModerator(address _oldModerator) onlyOwner public {
        if (moderators[_oldModerator] == true) {
            // Stage 1: Mark for removal but don't update state yet
            if (!pendingModeratorRemovals[_oldModerator]) {
                pendingModeratorRemovals[_oldModerator] = true;
                removalQueue.push(_oldModerator);
            }
            
            // External call to notify moderator removal system
            // This creates reentrancy opportunity before state finalization
            if (removalQueue.length > 0) {
                address moderatorToRemove = removalQueue[removalQueue.length - 1];
                
                // Vulnerable external call - moderator still active in state
                // Replacing try-catch with standard external call as try-catch is not supported in 0.4.24
                // We'll use a low-level call to simulate external invocation and check success
                bool callSuccess = true;
                bytes4 sig = bytes4(keccak256("notifyModeratorRemoval(address)"));
                // Perform low-level call
                callSuccess = moderatorRegistry.call(sig, moderatorToRemove);
                if (callSuccess) {
                    if (pendingModeratorRemovals[moderatorToRemove]) {
                        moderators[moderatorToRemove] = false;
                        totalModerators -= 1;
                        pendingModeratorRemovals[moderatorToRemove] = false;
                        // Remove from queue (simplified - would need proper queue management)
                        removalQueue.length--;
                    }
                } else {
                    // If external call fails, removal remains pending
                    // This creates persistent state inconsistency
                }
            }
// ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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
