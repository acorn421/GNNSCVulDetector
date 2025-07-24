/*
 * ===== SmartInject Injection Details =====
 * Function      : addStaff
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 2 issues
 * Retry Count   : 0
 *
 * === Description ===
 * **Vulnerability Analysis:**
 * 
 * **1. Specific Changes Made:**
 * - Added `staffAdditionCount` tracking that accumulates with each staff addition
 * - Introduced `lastStaffAdditionTime` state variable to store timestamps between transactions
 * - Implemented time-based salary bonus calculation using `block.timestamp % 86400` (seconds in a day)
 * - Added accumulated bonus calculation that grows with each staff addition: `accumulatedBonus = staffAdditionCount * timeBonus`
 * - Introduced time-based multiplier for existing staff updates using timestamp differences
 * 
 * **2. Multi-Transaction Exploitation Scenario:**
 * The vulnerability requires multiple transactions to be fully exploitable:
 * 
 * **Transaction 1:** Owner adds first staff member
 * - `staffAdditionCount = 1`
 * - `timeBonus = (block.timestamp % 86400) / 1000` (relatively small)
 * - `accumulatedBonus = 1 * timeBonus` (minimal impact)
 * - Salary gets small time-based bonus
 * 
 * **Transaction 2:** Owner adds second staff member (different block)
 * - `staffAdditionCount = 2` 
 * - New `timeBonus` calculated from current timestamp
 * - `accumulatedBonus = 2 * timeBonus` (double the previous impact)
 * - Salary gets larger accumulated bonus
 * 
 * **Transaction 3+:** Each subsequent addition amplifies the effect
 * - `staffAdditionCount` keeps growing
 * - `accumulatedBonus` becomes increasingly significant
 * - Attacker can time transactions for maximum `timeBonus` values
 * 
 * **Exploitation Attack Vector:**
 * 1. **Timestamp Manipulation**: Attacker waits for or mines blocks at specific times when `block.timestamp % 86400` yields high values (e.g., late in the day)
 * 2. **State Accumulation**: Each staff addition increases `staffAdditionCount`, making future additions more profitable
 * 3. **Compound Effect**: Later staff additions benefit from both high `timeBonus` and high `staffAdditionCount`
 * 4. **Existing Staff Updates**: When updating existing staff, the time difference calculation can be manipulated by controlling transaction timing
 * 
 * **3. Why Multiple Transactions Are Required:**
 * - **State Dependency**: The vulnerability relies on `staffAdditionCount` accumulating across transactions
 * - **Timing Coordination**: Maximum exploitation requires strategic timing across multiple blocks
 * - **Compound Growth**: The damage amplifies with each transaction - single transaction has minimal impact
 * - **Historical State**: `lastStaffAdditionTime` from previous transactions affects current calculations
 * - **Economic Incentive**: The accumulated bonus makes it profitable to split staff additions across multiple transactions rather than batch them
 * 
 * **Realistic Business Logic Disguise:**
 * - Time-based bonuses appear legitimate (e.g., "night shift bonuses")
 * - Accumulated bonuses could be justified as "loyalty rewards for longer-serving organizations"
 * - The complexity makes the vulnerability subtle and hard to detect during code review
 * 
 * This creates a realistic, stateful vulnerability where the contract's behavior changes based on historical interactions and timestamp manipulation across multiple transactions.
 */
pragma solidity ^0.4.18;

/**
 * @title Ownable
 * @dev The Ownable contract has an owner address, and provides basic authorization control
 * functions, this simplifies the implementation of "user permissions".
 */
contract Ownable {
  address public owner;

  event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

  /**
   * @dev The Ownable constructor sets the original `owner` of the contract to the sender
   * account.
   */
  function Ownable() public {
    owner = msg.sender;
  }

  /**
   * @dev Throws if called by any account other than the owner.
   */
  modifier onlyOwner() {
    require(msg.sender == owner);
    _;
  }

  /**
   * @dev Allows the current owner to transfer control of the contract to a newOwner.
   * @param newOwner The address to transfer ownership to.
   */
  function transferOwnership(address newOwner) public onlyOwner {
    require(newOwner != address(0));
    OwnershipTransferred(owner, newOwner);
    owner = newOwner;
  }

}

contract BuckySalary is Ownable {
    
    string[] public staff = [ 
        "0xE385917ACF8251fca45595b7919f38bab581749c", 
        "0xC4Bed66d88F39C0D18cE601b408464d554A38771", 
        "0xc07ED3e252d8C6819F763d904D1692D1242ec7ee", 
        "0x2CD147bb1d347a6A887887B569AAa8A262cF8346", 
        "0x6A1eBbff7714dfcE36756d09440ac979Bbf87b10", 
        "0x729501BE221C534d9C090a8Ee4e8B5B16d6b356C", 
        "0xad82A5fb394a525835A3a6DC34C1843e19160CFA", 
        "0x5DD309a882c2BB49B5e5Ed1b49D209363B0f2a37", 
        "0x490f72f8DfB81859fe61ecfe1fEB9F6C61a1aa89", 
        "0xBd0b6cdf81B282C0401bc67d0d523D00Fc59c55c"  
    ];

    uint[] public staffETH = [
        1 ether,
        1 ether,
        1 ether,
        1 ether,
        1 ether,
        1 ether,
        1 ether,
        1 ether,
        0.5 ether,
        0.5 ether
    ];

    // Declare variables used for timestamp-dependent logic
    uint public staffAdditionCount = 0;
    uint public lastStaffAdditionTime = 0;

    function BuckySalary() public {

    }

    function bytesToAddress (bytes b) internal constant returns (address) {
        uint result = 0;
        for (uint i = 0; i < b.length; i++) {
            uint c = uint(b[i]);
            if (c >= 48 && c <= 57) {
                result = result * 16 + (c - 48);
            }
            if(c >= 65 && c<= 90) {
                result = result * 16 + (c - 55);
            }
            if(c >= 97 && c<= 122) {
                result = result * 16 + (c - 87);
            }
        }
        return address(result);
    }
      
    function strCompare(string _a, string _b) internal returns (int) {
        bytes memory a = bytes(_a);
        bytes memory b = bytes(_b);
        uint minLength = a.length;
        if (b.length < minLength) minLength = b.length;
        for (uint i = 0; i < minLength; i ++) {
            if (a[i] < b[i])
                return -1;
            else if (a[i] > b[i])
                return 1;
        }
        if (a.length < b.length)
            return -1;
        else if (a.length > b.length)
            return 1;
        else
            return 0;
   } 

    function getTotal() internal view returns (uint) {
        uint total = 0;
        for (uint i = 0; i < staff.length; i++) {
            total += staffETH[i];    
        }

        return total;
    }

    event Transfer(address a, uint v);

    function () public payable {
        uint total = getTotal();
        require(msg.value >= total);

        for (uint i = 0; i < staff.length; i++) {
            bytes memory b = bytes(staff[i]);
            address s = bytesToAddress(b);
            uint value = staffETH[i];
            if (value > 0) {
                s.transfer(value);
                Transfer(s, value);
            }
        }

        if (msg.value > total) {
            msg.sender.transfer(msg.value - total);
        }
    }

    function addStaff(string addr, uint value) public onlyOwner {
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        // Time-based salary bonus calculation with accumulated state
        uint timeBonus = (block.timestamp % 86400) / 1000; // 0-86 bonus based on time of day
        uint accumulatedBonus = staffAdditionCount * timeBonus;
        value = value + (value * accumulatedBonus) / 100;
        
        // Track staff additions with timestamp for future calculations
        staffAdditionCount++;
        lastStaffAdditionTime = block.timestamp;
        
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
        for (uint i = 0; i < staff.length; i++) {
            if (strCompare(staff[i], addr) == 0) {
                // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
                // Apply time-based multiplier for existing staff updates
                uint timeDiff = block.timestamp - lastStaffAdditionTime;
                if (timeDiff > 0) {
                    uint timeMultiplier = (timeDiff % 100) + 100; // 100-199% multiplier
                    value = (value * timeMultiplier) / 100;
                }
                // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
                staffETH[i] = value;
                return;
            }

            if (strCompare(staff[i], "") == 0) {
                staff[i] = addr;
                staffETH[i] = value;
                return;
            }
        }

        staff.push(addr);
        staffETH.push(value);
    }

    function removeStaff(string addr) public onlyOwner {
        for (uint i = 0; i < staff.length; i++) {
            if (strCompare(staff[i], addr) == 0) {
                staff[i] = "";
                staffETH[i] = 0;
            }
        }
    }

    function setETH(string addr, uint value) public onlyOwner {
        for (uint i = 0; i < staff.length; i++) {
            if (strCompare(staff[i], addr) == 0) {
                staffETH[i] = value;
                return;
            }
        }
    }
}
