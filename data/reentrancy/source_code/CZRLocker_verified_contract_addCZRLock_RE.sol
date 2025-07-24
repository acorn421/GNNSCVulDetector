/*
 * ===== SmartInject Injection Details =====
 * Function      : addCZRLock
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 2 findings
 * Total Found   : 6 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-benign (SWC-107)
 * 2. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to addr.call() before state updates to lockedCZRMap. The vulnerability requires multiple transactions to exploit:
 * 
 * **Specific Changes Made:**
 * 1. Added a check for contract code at the target address using `addr.code.length > 0`
 * 2. Inserted an external call `addr.call(abi.encodeWithSignature("onLockAdded(uint256,uint256)", amount, lockMonth))` before the state update
 * 3. Added a comment to make the callback seem like a legitimate notification feature
 * 4. Placed the external call after parameter validation but before state modifications
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 1. **Transaction 1**: Owner calls addCZRLock with a malicious contract address
 * 2. **During Transaction 1**: The malicious contract's fallback/onLockAdded function is triggered
 * 3. **Reentrancy occurs**: The malicious contract calls back into addCZRLock (or other functions) before the original state update completes
 * 4. **Transaction 2+**: Subsequent calls can exploit the inconsistent state where the lock hasn't been added yet but the external call has been made
 * 
 * **Why Multi-Transaction Vulnerability:**
 * - The vulnerability requires the attacker to first deploy a malicious contract at the target address
 * - The malicious contract must implement the callback mechanism to re-enter
 * - State accumulation occurs as multiple locks can be added in unexpected ways during reentrancy
 * - The timing window between external call and state update creates a stateful vulnerability window
 * - Each reentrancy call can add locks in a way that bypasses intended business logic
 * 
 * **Exploitation Pattern:**
 * ```solidity
 * // Malicious contract deployed at addr
 * function onLockAdded(uint256 amount, uint256 lockMonth) external {
 *     // Re-enter to add more locks before original state update
 *     CZRLocker(msg.sender).addCZRLock(address(this), 0, amount, lockMonth);
 * }
 * ```
 * 
 * This creates a realistic vulnerability that appears to be a legitimate notification system but allows for stateful reentrancy exploitation across multiple transactions.
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

interface token {
    function transferFrom(address _from, address _to, uint256 _value) external returns (bool success);
}

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
        emit RemoveLock(addr, index);
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
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Notify the address about the lock being added (external call before state update)
        uint size;
        assembly { size := extcodesize(addr) }
        if (size > 0) {
            bool success = addr.call(bytes4(keccak256("onLockAdded(uint256,uint256)")), amount, lockMonth);
            // Continue regardless of success for user experience
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        lockedCZRMap[addr].push(LockedCZR(startLockTime, lockMonth, amount, 0));
        uint index = lockedCZRMap[addr].length - 1;
        emit AddLock(addr, index, startLockTime, lockMonth, amount);
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
                    
                lock.unlockedAmount += unlockAmount;
                lock.lockedAmount -= unlockAmount;
                        
                t.transferFrom(owner, addr, unlockAmount);
                emit Unlock(addr, i, unlockAmount);
                
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
