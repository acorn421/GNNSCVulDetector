/*
 * ===== SmartInject Injection Details =====
 * Function      : changeSearcher
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 1 findings
 * Total Found   : 7 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-benign (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by:
 * 1. Moving the validation logic after the external call to seeker.identify()
 * 2. Adding state modification of the 'value' variable after the external call
 * 3. Creating a time window where the seeker is set but validation hasn't completed
 * 4. Enabling multi-transaction exploitation where:
 *    - Transaction 1: Attacker calls changeSearcher() with malicious contract
 *    - During identify() call, malicious contract can re-enter and call other functions (like write, peek, etc.) using the newly set seeker
 *    - The state change to 'value' persists between transactions
 *    - Transaction 2+: Attacker can exploit the compromised state through subsequent calls
 * 5. The vulnerability requires multiple transactions because the malicious seeker must be set first, then exploited in subsequent calls to other functions that use the seeker
 */
pragma solidity ^0.4.24;

// Searcher is an interface for contracts that want to be notified of incoming data
//
contract Searcher {

    // poke is called when new data arrives
    //
    function poke() public;

    // this is called to ensure that only valid Searchers can be added to the Lighthouse - returns an arbitrarily chosen number
    //
    function identify() external pure returns(uint) {
        return 0xda4b055; 
    }
}

// for operation of this contract see the readme file.
//
contract Lighthouse {
    
    address public auth = msg.sender; // ownable model. No real value in making it transferrable.

    Searcher seeker;                  // a single contract that can be notified of data changes

    uint value;                       // holds all the data bit fiddled into a single 32 byte word.

    uint maxAge;                      // if non zero, sets a limit to data validity

    // admin functions
    
    modifier onlyAuth {
        require(auth == msg.sender, "Unauthorised access");
        _;
    }

    function changeAuth(address newAuth) public onlyAuth {
        auth = newAuth;
    }

    function changeSearcher(Searcher newSeeker) public onlyAuth {
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // Vulnerability: Set seeker first, then call external contract
        seeker = newSeeker;
        
        // External call that can trigger reentrancy
        uint result = seeker.identify();
        
        // State modification after external call - creates window for reentrancy
        if (result == 0xda4b055) {
            // Additional state change that persists across transactions
            // This creates a multi-transaction vulnerability pattern
            value = (value & 0xffffffffffffffffffffffffffffffff0000000000000000) | uint128(now);
        } else {
            // Revert only after external call and state modifications
            revert("invalid searcher");
        }
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
    }

    function setMaxAge(uint newMaxAge) public onlyAuth {
        maxAge = newMaxAge;
    }
    
    function notTooLongSinceUpdated() public view returns (bool) {
        uint since = now - ((value >> 128) & 
        0x000000000000000000000000000000000000000000000000ffffffffffffffff);
        return (since < maxAge) || (maxAge == 0);
    }
    
    function peekData() external view returns (uint128 v,bool b) {
        v = uint128(value);
        b = notTooLongSinceUpdated() && value != 0;
        return;
    }
    
    function peekUpdated()  external view returns (uint32 v,bool b) {
        uint v2 = value >> 128;
        v = uint32(v2);
        b = notTooLongSinceUpdated() && value != 0;
        return;
    }
    
    function peekLastNonce() external view returns (uint32 v,bool b) {
        uint v2 = value >> 192;
        v = uint32(v2);
        b = notTooLongSinceUpdated() && value != 0;
        return;
    }

    function peek() external view returns (bytes32 v ,bool ok) {
        v = bytes32(value & 0x00000000000000000000000000000000ffffffffffffffffffffffffffffffff);
        ok = notTooLongSinceUpdated() && value != 0;
        return;
    }
    
    function read() external view returns (bytes32 x) {
        require(notTooLongSinceUpdated() && value != 0, "Invalid data stored");
        return bytes32(value & 0x00000000000000000000000000000000ffffffffffffffffffffffffffffffff);
    }
    
    function write(uint  DataValue, uint nonce) external onlyAuth {
        require ((DataValue >> 128) == 0, "Value too large");
        require ((nonce >> 32) == 0, "Nonce too large");
        value = DataValue + (nonce << 192) + (now << 128) ;
        if (address(seeker) != address(0)) {
            seeker.poke();
        }
    }
}