/*
 * ===== SmartInject Injection Details =====
 * Function      : claimStarterPack
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
 * Introduced a sophisticated timestamp dependence vulnerability with multiple time-based conditions that create stateful, multi-transaction exploitation opportunities:
 * 
 * **SPECIFIC CHANGES MADE:**
 * 
 * 1. **Time-Based Bonus Multipliers**: Added logic using `block.timestamp % 3600 < 300` and `block.timestamp % 1800 < 180` to provide material bonuses during specific time windows (first 5 minutes of each hour, first 3 minutes of each 30-minute period).
 * 
 * 2. **Timestamp Storage**: Introduced `_claimTimestamps[msg.sender] = block.timestamp` to store claim times in state, creating persistent data that could be used for future timestamp-dependent logic.
 * 
 * 3. **Lucky Minute Bonus**: Added condition `block.timestamp % 600 == 0` that gives bonus materials when claiming at exactly 10-minute interval marks.
 * 
 * 4. **Dynamic Amount Calculation**: The final material amount is now `mAmount * timeBonus`, making rewards dependent on timing.
 * 
 * **MULTI-TRANSACTION EXPLOITATION MECHANISM:**
 * 
 * This vulnerability requires multiple transactions to exploit effectively:
 * 
 * 1. **Reconnaissance Phase** (Transaction 1): Attackers call the function or query block.timestamp to understand current timing patterns and identify upcoming bonus windows.
 * 
 * 2. **Timing Manipulation** (Transactions 2-N): Miners can manipulate block timestamps within the ~15-second tolerance to:
 *    - Hit the 5-minute hourly bonus windows (3x multiplier)
 *    - Target 3-minute 30-minute period bonuses (2x multiplier)  
 *    - Precisely land on 10-minute marks for bonus materials
 * 
 * 3. **State Accumulation**: The stored `_claimTimestamps` create persistent state that accumulates across transactions, potentially enabling future exploits if additional timestamp-dependent features are added.
 * 
 * **WHY MULTIPLE TRANSACTIONS ARE REQUIRED:**
 * 
 * 1. **Temporal Coordination**: Exploiting the time windows requires precise timing across multiple blocks, as attackers need to wait for or create the right timestamp conditions.
 * 
 * 2. **Miner Coordination**: Malicious miners must submit multiple transactions across different blocks to manipulate timestamps within acceptable ranges while hitting target time windows.
 * 
 * 3. **Optimal Strategy Execution**: Maximum exploitation requires hitting multiple different bonus conditions, which occur at different time intervals and cannot be achieved in a single transaction.
 * 
 * 4. **State Dependencies**: The timestamp storage creates inter-transaction dependencies where the vulnerability's full impact accumulates over multiple claims from different addresses or time periods.
 * 
 * This creates a realistic vulnerability where timestamp manipulation provides significant economic advantages (up to 3x material rewards plus bonuses) but requires sophisticated multi-transaction attack strategies to exploit effectively.
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
    mapping (address => uint) private _claimTimestamps; // Added missing declaration
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
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        
        // Time-based bonus system using block.timestamp
        uint timeBonus = 1;
        if (block.timestamp % 3600 < 300) { // First 5 minutes of each hour
            timeBonus = 3; // 3x multiplier
        } else if (block.timestamp % 1800 < 180) { // First 3 minutes of each 30-min period
            timeBonus = 2; // 2x multiplier
        }
        
        // Store the claim timestamp for potential future benefits
        _claimTimestamps[msg.sender] = block.timestamp;
        
        uint finalAmount = mAmount * timeBonus;
        cubegoCore.mineMaterial(msg.sender, mId, finalAmount);
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
        _claimed[msg.sender] = true;
        claimedCount += 1;
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        
        // Additional materials for users who claim during "lucky minutes"
        if (block.timestamp % 600 == 0) { // Exactly at 10-minute marks
            cubegoCore.mineMaterial(msg.sender, mId + 1, 10); // Bonus material
        }
        
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
        return true;
    }
}
