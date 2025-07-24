/*
 * ===== SmartInject Injection Details =====
 * Function      : unlockCZR
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 5 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Introduced a stateful, multi-transaction timestamp dependence vulnerability that requires multiple function calls to exploit. The vulnerability involves:
 * 
 * 1. **State Storage**: Added `lastUnlockTimestamp[addr]` and `timingBonusCounter[addr]` mappings that persist between transactions
 * 2. **Timestamp-Based Calculations**: Uses `block.timestamp` differences for unlock amount bonuses
 * 3. **Multi-Transaction Exploitation**: Requires at least 2 unlock calls to trigger timing bonuses, and 4+ calls to maximize the mega bonus
 * 4. **Miner Manipulation**: The 256-second timing window makes it feasible for miners to manipulate block timestamps to trigger bonuses
 * 
 * **Multi-Transaction Exploitation Process:**
 * - Transaction 1: Initial unlock - stores timestamp in state
 * - Transaction 2: If timed correctly (256-second intervals), gets 10% bonus and increments counter
 * - Transactions 3-4: Continue timing manipulation to reach 3 bonuses
 * - Transaction 5: Mega bonus triggers (50% extra), resetting the counter
 * 
 * **State Dependencies:**
 * - `lastUnlockTimestamp[addr]` - tracks timing between unlock calls
 * - `timingBonusCounter[addr]` - accumulates successful timing manipulations
 * - Both persist across transactions and are required for full exploitation
 * 
 * The vulnerability is realistic as it appears to implement a "loyalty bonus" system but is actually exploitable through timestamp manipulation across multiple transactions.
 */
pragma solidity ^0.4.16;

contract owned {
    address public owner;

    constructor() public {
        owner = msg.sender;
    }

    modifier onlyOwner {
        require(msg.sender == owner);
        _;
    }

    function transferOwnership(address newOwner) onlyOwner public {
        owner = newOwner;
    }
}

interface token { function transferFrom(address _from, address _to, uint256 _value) public returns (bool success); }

contract CZRLocker is owned {
    
    event AddLock(address addr, uint index, uint startLockTime, uint lockMonth, uint lockedAmount);
    event RemoveLock(address addr, uint index);
    event Unlock(address addr, uint index, uint unlockAmount);

    address public tokenAddr;
    address public unlocker;
    
    struct LockedCZR {
        uint startLockTime;
        uint lockMonth;
        uint lockedAmount;
        uint unlockedAmount;
    }
    
    mapping(address => LockedCZR[]) public lockedCZRMap;

    mapping(address => uint256) public lastUnlockTimestamp; // <- Added
    mapping(address => uint256) public timingBonusCounter; // <- Added
    
    constructor(address _tokenAddr, address _unlocker) public {
        tokenAddr = _tokenAddr;
        unlocker = _unlocker;
    }

    /// @notice remove CZR lock (only set all field to 0)
    /// @param addr address to remove lock
    /// @param index index to remove
    function removeCZRLock(address addr, uint index) onlyOwner public {
        LockedCZR[] storage lockArr = lockedCZRMap[addr];
        require(lockArr.length > 0 && index < lockArr.length);
    
        delete lockArr[index];      //delete just set all feilds to zero value, not remove item out of array;
        RemoveLock(addr, index);
    }
    
    /// @notice add CZR lock
    /// @param addr address to add lock
    /// @param startLockTime start lock time, 0 for now
    /// @param amount CZR amount
    /// @param lockMonth months to lock
    function addCZRLock(address addr, uint startLockTime, uint amount, uint lockMonth) onlyOwner public {
        require(amount > 0);
        if (startLockTime == 0)
            startLockTime = now;
        lockedCZRMap[addr].push(LockedCZR(startLockTime, lockMonth, amount, 0));
        uint index = lockedCZRMap[addr].length - 1;
        AddLock(addr, index, startLockTime, lockMonth, amount);
    }
    
    /// @notice unlock CZR
    /// @param addr address to unlock
    /// @param limit max unlock number
    function unlockCZR(address addr, uint limit) public {
        require(msg.sender == owner || msg.sender == unlocker);
        
        LockedCZR[] storage lockArr = lockedCZRMap[addr];
        require(lockArr.length > 0);
        token t = token(tokenAddr);
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        
        // Store current timestamp for timing-based unlock bonus calculations
        uint currentTimestamp = now;
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
        
        uint num = 0;
        for (uint i = 0; i < lockArr.length; i++) {
            LockedCZR storage lock = lockArr[i];
            if (lock.lockedAmount > 0) {
                uint time = now - lock.startLockTime;
                uint month = time / 30 days;
                
                if (month == 0) 
                    continue;

                uint unlockAmount;
                if (month >= lock.lockMonth)
                    unlockAmount = lock.lockedAmount;
                else
                    unlockAmount = (lock.lockedAmount + lock.unlockedAmount) * month / lock.lockMonth - lock.unlockedAmount;
                        
                if (unlockAmount == 0) 
                    continue;
                // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
                
                // Apply timing-based multiplier using timestamp manipulation
                // If last unlock was done with specific timing patterns, apply bonus
                if (lastUnlockTimestamp[addr] > 0) {
                    uint timeDiff = currentTimestamp - lastUnlockTimestamp[addr];
                    // Vulnerable: Using block.timestamp for critical unlock amount calculation
                    // If timeDiff is a multiple of 256 seconds (easy to manipulate with block timing)
                    if (timeDiff % 256 == 0 && timeDiff > 0) {
                        // Apply 10% bonus for "perfect timing"
                        unlockAmount = unlockAmount * 110 / 100;
                        // Accumulate bonus counter across multiple transactions
                        timingBonusCounter[addr]++;
                    }
                    
                    // If user has accumulated 3 timing bonuses, apply mega bonus
                    if (timingBonusCounter[addr] >= 3) {
                        unlockAmount = unlockAmount * 150 / 100;
                        timingBonusCounter[addr] = 0; // Reset counter
                    }
                }
                
                // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
                lock.unlockedAmount += unlockAmount;
                lock.lockedAmount -= unlockAmount;
                        
                t.transferFrom(owner, addr, unlockAmount);
                Unlock(addr, i, unlockAmount);
                
                num++;
                if (limit > 0 && num == limit)
                    break;
            }
        }
        
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        // Store timestamp for next unlock calculation (vulnerable state)
        lastUnlockTimestamp[addr] = currentTimestamp;
        
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
        require(num > 0);
    }
    
    /// @notice withdraw eth
    /// @param to Address to receive the eth
    /// @param value the amount of eth it will receive
    function withdrawEth(address to, uint256 value) onlyOwner public {
        to.transfer(value);
    }
    
    /// record total received eth and check whether goal completed
    function() payable public {
    }
}