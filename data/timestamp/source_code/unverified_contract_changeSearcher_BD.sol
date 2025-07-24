/*
 * ===== SmartInject Injection Details =====
 * Function      : changeSearcher
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 9 issues
 * Retry Count   : 0
 *
 * === Description ===
 * This modification introduces a stateful, multi-transaction timestamp dependence vulnerability by implementing time-based controls for searcher changes. The vulnerability requires multiple transactions over time to exploit:
 * 
 * **Specific Changes Made:**
 * 1. Added a cooldown period check using `now >= lastSearcherChange + searcherCooldown`
 * 2. Introduced state variables that persist between transactions:
 *    - `lastSearcherChange`: Stores when the searcher was last changed
 *    - `searcherActivationTime`: Stores when the new searcher becomes fully active
 *    - `searcherTrustLevel`: Tracks the trust level of current searcher over time
 * 3. Uses block.timestamp (`now`) for critical time-based logic without proper validation
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 1. **Transaction 1**: Admin calls `changeSearcher()` with a malicious searcher contract
 * 2. **Wait Period**: Attacker waits for the cooldown period to pass
 * 3. **Transaction 2**: Admin calls `changeSearcher()` again to change to another searcher
 * 4. **Timestamp Manipulation**: Miners can manipulate block timestamps to:
 *    - Bypass cooldown periods by setting timestamps artificially forward
 *    - Affect activation timing across multiple blocks
 *    - Manipulate the trust level progression system
 * 
 * **Why Multi-Transaction Vulnerability:**
 * - The vulnerability requires persistent state changes (`lastSearcherChange`, `searcherActivationTime`) that accumulate across transactions
 * - Exploitation requires coordination across multiple blocks/transactions over time
 * - The cooldown mechanism creates a time dependency that can only be exploited through sequential transactions
 * - Cannot be exploited in a single atomic transaction due to the time-based state requirements
 * 
 * **Real-World Impact:**
 * - Miners could collude to manipulate block timestamps to bypass security controls
 * - The 15-second timestamp tolerance in Ethereum allows for manipulation
 * - Creates a race condition where legitimate and malicious searcher changes compete over time
 * - Trust level system becomes unreliable due to timestamp manipulation
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

    // === Added missing state variables for compilation ===
    uint public lastSearcherChange;   // timestamp of last searcher change
    uint public searcherCooldown = 1 hours; // cooldown period, can be adjusted as needed
    uint public searcherActivationTime; // when the searcher becomes active
    uint public activationDelay = 1 hours; // activation delay, can be adjusted as needed
    uint public searcherTrustLevel;   // trust level for searcher
    // ===============================================

    // admin functions
    
    modifier onlyAuth {
        require(auth == msg.sender, "Unauthorised access");
        _;
    }

    function changeAuth(address newAuth) public onlyAuth {
        auth = newAuth;
    }

    function changeSearcher(Searcher newSeeker) public onlyAuth {
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        // Check if enough time has passed since last change (cooldown period)
        require(now >= lastSearcherChange + searcherCooldown, "Searcher change cooldown not met");
        
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
        seeker = newSeeker;
        require(seeker.identify() == 0xda4b055,"invalid searcher");
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        
        // Store when this searcher was set and when it will become active
        lastSearcherChange = now;
        searcherActivationTime = now + activationDelay;
        
        // The searcher becomes progressively more trusted over time
        searcherTrustLevel = 1; // Reset trust level for new searcher
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
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
