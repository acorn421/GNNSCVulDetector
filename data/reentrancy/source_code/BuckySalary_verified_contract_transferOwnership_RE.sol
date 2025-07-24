/*
 * ===== SmartInject Injection Details =====
 * Function      : transferOwnership
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 3 findings
 * Total Found   : 3 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-benign (SWC-107)
 * 3. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability through a two-phase ownership transfer mechanism:
 * 
 * **Specific Changes Made:**
 * 1. **Added State Variables**: `pendingOwners` mapping and `pendingOwner` address to track transfer state across transactions
 * 2. **Implemented Two-Phase Transfer**: First call marks owner as pending, second call completes the transfer
 * 3. **Inserted External Call**: Added `newOwner.call()` before state updates, creating reentrancy vulnerability window
 * 4. **Violated Checks-Effects-Interactions**: State modifications occur after external call, enabling manipulation
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 1. **Transaction 1**: Owner calls `transferOwnership(maliciousContract)` 
 *    - `pendingOwners[maliciousContract] = true`
 *    - External call to `maliciousContract.validateOwnership()`
 *    - Malicious contract re-enters with different address, bypassing pending check
 *    - Multiple ownership transfers can be initiated simultaneously
 * 
 * 2. **Transaction 2**: Malicious contract calls `transferOwnership(attacker)` 
 *    - Since `pendingOwners[attacker]` is false, it enters first phase again
 *    - During re-entrance, can manipulate pending state before legitimate transfer completes
 *    - Can potentially claim ownership through race condition
 * 
 * 3. **Transaction 3**: Complete ownership transfer with corrupted state
 *    - Pending state manipulation allows attacker to finalize unauthorized ownership
 * 
 * **Why Multi-Transaction is Required:**
 * - The vulnerability exploits the persistent state (`pendingOwners` mapping) that accumulates across transactions
 * - First transaction establishes the vulnerable state, subsequent transactions exploit it
 * - Single-transaction exploitation is prevented by the two-phase mechanism requiring state persistence
 * - The external call creates a window where state can be manipulated across multiple re-entrant calls
 * - Race conditions between legitimate and malicious ownership transfers require multiple transaction sequences
 * 
 * **Realistic Production Vulnerability:**
 * - Mimics real-world multi-signature or validation patterns
 * - Two-phase transfer mechanism is common in production contracts
 * - External validation calls are realistic for ownership verification
 * - State persistence across transactions is essential for the exploit
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
  // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
mapping(address => bool) public pendingOwners;
  address public pendingOwner;

  function transferOwnership(address newOwner) public onlyOwner {
    require(newOwner != address(0));
    
    // First phase: Mark as pending and validate with external call
    if (!pendingOwners[newOwner]) {
      pendingOwner = newOwner;
      pendingOwners[newOwner] = true;
      
      // External call to validate ownership transfer - vulnerable to reentrancy
      if (newOwner.call(bytes4(keccak256("validateOwnership(address)")), address(this))) {
        // State modification happens after external call - vulnerability window
        OwnershipTransferred(owner, newOwner);
        owner = newOwner;
        
        // Reset pending state
        pendingOwner = address(0);
        pendingOwners[newOwner] = false;
      }
    } else {
      // Second phase: Complete transfer if already pending
      OwnershipTransferred(owner, newOwner);
      owner = newOwner;
      
      // Reset pending state
      pendingOwner = address(0);
      pendingOwners[newOwner] = false;
    }
// ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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
            bytes b = bytes(staff[i]);
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