/*
 * ===== SmartInject Injection Details =====
 * Function      : removeStaff
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 1 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Introduced a timestamp-dependent multi-transaction vulnerability where staff removal requires a two-step process with a time delay. The vulnerability exploits block.timestamp manipulation by miners who can adjust block timestamps within a ~15 second window. This creates a stateful, multi-transaction attack where:
 * 
 * 1. **Transaction 1**: Owner initiates removal request, storing timestamp in state
 * 2. **Transaction 2**: After delay period, owner completes removal based on timestamp comparison
 * 
 * **Exploitation Scenario**:
 * - A malicious miner or attacker who compromises the owner account can manipulate the removal process
 * - In Transaction 1, they initiate removal and the current block.timestamp is stored
 * - In Transaction 2, they can mine a block with a manipulated timestamp that makes it appear the delay has passed when it hasn't, or prevent removal by mining blocks with earlier timestamps
 * - The vulnerability requires persistent state (removalRequests and removalTimestamps mappings) and multiple transactions to exploit
 * 
 * **Multi-Transaction Requirement**: 
 * - Cannot be exploited in a single transaction due to the state check mechanism
 * - Requires initial setup transaction to establish removal request
 * - Requires second transaction after delay period to complete removal
 * - State persists between transactions enabling the timestamp manipulation attack
 * 
 * This creates a realistic vulnerability pattern seen in many DeFi protocols that implement time-locked operations for security purposes.
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

    function BuckySalary() public { }

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
        for (uint i = 0; i < staff.length; i++) {
            if (strCompare(staff[i], addr) == 0) {
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

    // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
    // *** CHANGED mapping keys to bytes32 for compatibility ***
    mapping(bytes32 => uint) removalRequests;
    mapping(bytes32 => uint) removalTimestamps;
    uint public removalDelay = 1 hours; // Security delay for staff removal

    function removeStaff(string addr) public onlyOwner {
        bytes32 addrKey = keccak256(addr);
        // If no pending removal request, create one
        if (removalRequests[addrKey] == 0) {
            removalRequests[addrKey] = 1;
            removalTimestamps[addrKey] = block.timestamp;
            return;
        }
        // If removal request exists, check if delay has passed
        if (removalRequests[addrKey] == 1) {
            // Vulnerability: Using block.timestamp without proper validation
            // Miners can manipulate timestamp within ~15 second window
            if (block.timestamp >= removalTimestamps[addrKey] + removalDelay) {
                // Process the removal
                for (uint i = 0; i < staff.length; i++) {
                    if (strCompare(staff[i], addr) == 0) {
                        staff[i] = "";
                        staffETH[i] = 0;
                    }
                }
                // Clear the removal request
                removalRequests[addrKey] = 0;
                removalTimestamps[addrKey] = 0;
// ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
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