/*
 * ===== SmartInject Injection Details =====
 * Function      : write
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
 * 1. reentrancy-no-eth (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by: 1) Moving the external call to seeker.poke() BEFORE state updates, 2) Adding a second external call that depends on the previous state value, creating a multi-transaction attack window, 3) Storing the old value which can be accessed and manipulated by the seeker contract during reentrancy, 4) Creating a dependency chain where the vulnerability requires multiple transactions to fully exploit - first to set up state, then to trigger the reentrancy, and finally to manipulate the accumulated state changes.
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
        seeker = newSeeker;
        require(seeker.identify() == 0xda4b055,"invalid searcher");
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
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Store the old value for the external call
        uint oldValue = value;
        
        // Make external call BEFORE updating state - classic reentrancy pattern
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        if (address(seeker) != address(0)) {
            seeker.poke();
        }
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Update state after external call - vulnerable to reentrancy
        // The seeker can now call write() again during poke() and manipulate state
        value = DataValue + (nonce << 192) + (now << 128);
        
        // Additional vulnerability: allow seeker to access and modify based on old value
        // This creates a multi-transaction dependency where previous state affects current execution
        if (oldValue != 0 && address(seeker) != address(0)) {
            // This creates a window where state can be manipulated across multiple calls
            // The seeker contract can store and use the oldValue to perform stateful attacks
            seeker.poke();
        }
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
    }
}