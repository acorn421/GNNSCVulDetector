/*
 * ===== SmartInject Injection Details =====
 * Function      : addCZRLock
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 4 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Introduced a stateful, multi-transaction timestamp dependence vulnerability where:
 * 
 * 1. **Timestamp-based bonus calculation**: The function now calculates a 10% bonus for locks created within the same block timestamp as the previous lock
 * 2. **State accumulation**: The vulnerability requires multiple addCZRLock calls to exploit, as it depends on comparing current timestamp with previously stored timestamps in lockedCZRMap
 * 3. **Miner manipulation**: Miners can manipulate block timestamps within the allowed drift (~15 seconds) to group multiple lock transactions into the same block timestamp, enabling repeated bonus accumulation
 * 4. **Cross-transaction exploitation**: An attacker (working with a miner) could:
 *    - Transaction 1: Create initial lock with amount X
 *    - Transaction 2: Create second lock with amount Y in same block → receives 10% bonus
 *    - Transaction 3: Create third lock with amount Z in same block → receives another 10% bonus
 *    - This pattern continues, allowing accumulation of undeserved bonuses
 * 
 * The vulnerability is multi-transaction because:
 * - It requires at least 2 separate addCZRLock calls to trigger
 * - Each subsequent call within the same block timestamp increases the exploited amount
 * - The state from previous transactions (stored timestamps) enables the vulnerability
 * - Cannot be exploited in a single transaction as it requires comparison with existing lock data
 * 
 * This creates a realistic timestamp dependence where the timing relationship between multiple transactions determines the bonus calculation, making it a genuine multi-transaction, stateful vulnerability.
 */
pragma solidity ^0.4.16;

contract owned {
    address public owner;

    function owned() public {
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
    
    function CZRLocker(address _tokenAddr, address _unlocker) public {
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
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        
        // Vulnerable: Time-based bonus calculation that accumulates across transactions
        uint timeBonus = 0;
        if (lockedCZRMap[addr].length > 0) {
            // Get the last lock entry timestamp
            uint lastLockTime = lockedCZRMap[addr][lockedCZRMap[addr].length - 1].startLockTime;
            // Vulnerable: If locks are created within same block, apply cumulative bonus
            if (now == lastLockTime) {
                timeBonus = amount * 10 / 100; // 10% bonus for same-block locks
            }
        }
        
        // Vulnerable: Store current block timestamp for time-window validation
        uint effectiveAmount = amount + timeBonus;
        
        lockedCZRMap[addr].push(LockedCZR(startLockTime, lockMonth, effectiveAmount, 0));
        uint index = lockedCZRMap[addr].length - 1;
        AddLock(addr, index, startLockTime, lockMonth, effectiveAmount);
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
    }
    
    /// @notice unlock CZR
    /// @param addr address to unlock
    /// @param limit max unlock number
    function unlockCZR(address addr, uint limit) public {
        require(msg.sender == owner || msg.sender == unlocker);
        
        LockedCZR[] storage lockArr = lockedCZRMap[addr];
        require(lockArr.length > 0);
        token t = token(tokenAddr);
        
        uint num = 0;
        for (uint i = 0; i < lockArr.length; i++) {
            var lock = lockArr[i];
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
                    
                lock.unlockedAmount += unlockAmount;
                lock.lockedAmount -= unlockAmount;
                        
                t.transferFrom(owner, addr, unlockAmount);
                Unlock(addr, i, unlockAmount);
                
                num++;
                if (limit > 0 && num == limit)
                    break;
            }
        }
        
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