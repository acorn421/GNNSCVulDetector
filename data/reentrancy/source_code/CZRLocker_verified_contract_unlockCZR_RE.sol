/*
 * ===== SmartInject Injection Details =====
 * Function      : unlockCZR
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 1 findings
 * Total Found   : 4 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-events (SWC-107)
 *
 * === Description ===
 * **Vulnerability Injection Details:**
 * 
 * **1. Specific Changes Made:**
 * - **Reordered Operations**: Moved the external call `t.transferFrom(owner, addr, unlockAmount)` to execute BEFORE the state updates (`lock.unlockedAmount += unlockAmount` and `lock.lockedAmount -= unlockAmount`)
 * - **Violation of Checks-Effects-Interactions Pattern**: The function now performs interactions (external calls) before effects (state changes), creating a reentrancy window
 * - **Preserved Function Logic**: All original calculations and requirements remain intact
 * 
 * **2. Multi-Transaction Exploitation Scenario:**
 * 
 * **Transaction 1 - Setup Phase:**
 * - Attacker deploys a malicious contract that implements the token interface
 * - Attacker gets this malicious contract set as the `tokenAddr` or creates locks with specific timing
 * - The malicious contract's `transferFrom` function contains a callback that re-invokes `unlockCZR`
 * 
 * **Transaction 2 - Exploitation Phase:**
 * - Attacker calls `unlockCZR(attackerAddress, 0)` 
 * - Function calculates `unlockAmount` based on current state
 * - External call `t.transferFrom(owner, addr, unlockAmount)` triggers malicious callback
 * - **Reentrancy Window**: Callback re-invokes `unlockCZR` before state updates complete
 * - Second invocation sees unchanged state (same `lockedAmount`, same `unlockedAmount`)
 * - Calculates same `unlockAmount` and triggers another transfer
 * - Process repeats, draining more tokens than legitimately unlocked
 * 
 * **Transaction 3+ - Continued Exploitation:**
 * - State persistence between transactions allows attacker to:
 *   - Accumulate unlocked tokens across multiple calls
 *   - Exploit the time-based unlock calculation repeatedly
 *   - Each transaction builds on the state corruption from previous transactions
 * 
 * **3. Why Multi-Transaction Exploitation is Required:**
 * 
 * **State Persistence Dependency:**
 * - The vulnerability relies on `lockedCZRMap[addr]` state persisting between transactions
 * - Attacker must first establish lock entries in one transaction, then exploit in subsequent calls
 * - The time-based unlock calculation depends on `lock.startLockTime` from previous transactions
 * 
 * **Accumulated State Corruption:**
 * - Each reentrancy call corrupts the state incrementally
 * - Multiple transactions allow the attacker to:
 *   - Build up `unlockedAmount` values inconsistently
 *   - Exploit the same `lockedAmount` multiple times across different transaction contexts
 *   - Accumulate unauthorized token transfers over time
 * 
 * **Cross-Transaction Attack Vector:**
 * - The attacker cannot complete the full exploit in a single transaction because:
 *   - Lock setup and exploitation require separate transaction contexts
 *   - Time-based calculations may need actual block time progression
 *   - State corruption accumulates most effectively across multiple invocations with persistent storage
 * 
 * **Realistic Attack Flow:**
 * 1. **T1**: Attacker creates locks with specific timing via `addCZRLock`
 * 2. **T2**: Time passes, attacker invokes `unlockCZR` with malicious callback
 * 3. **T3+**: Continued exploitation builds on corrupted state from T2, draining additional tokens
 * 
 * This creates a genuinely dangerous multi-transaction reentrancy vulnerability that requires state accumulation and persistence to be fully exploitable.
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
                // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
                
                // VULNERABILITY: External call before state update allows reentrancy
                // The transfer triggers a callback to the recipient before state is updated
                t.transferFrom(owner, addr, unlockAmount);
                
                // State updates happen AFTER external call - vulnerable to reentrancy
                // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
                lock.unlockedAmount += unlockAmount;
                lock.lockedAmount -= unlockAmount;
                        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
                        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
                        
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