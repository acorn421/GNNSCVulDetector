/*
 * ===== SmartInject Injection Details =====
 * Function      : scheduleUpdate
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 7 issues
 * Retry Count   : 0
 *
 * === Description ===
 * This introduces a timestamp dependence vulnerability that requires multiple transactions to exploit. The vulnerability allows an attacker to manipulate the execution time of scheduled updates by taking advantage of miner control over block timestamps. An attacker (or malicious miner) can first schedule an update, then manipulate the timestamp in subsequent blocks to either delay or accelerate the execution of the scheduled update. This creates a multi-transaction attack where: 1) First transaction schedules an update, 2) Attacker waits and potentially influences block timestamps, 3) Second transaction executes the update at a manipulated time. The state persists between transactions through the scheduledTime, scheduledValue, scheduledNonce, and hasPendingUpdate variables.
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

    // === FALLBACK INJECTION: Timestamp Dependence ===
    // This function was added as a fallback when existing functions failed injection
    uint public scheduledTime;
    uint public scheduledValue;
    uint public scheduledNonce;
    bool public hasPendingUpdate = false;
    
    function scheduleUpdate(uint DataValue, uint nonce, uint delaySeconds) external onlyAuth {
        require ((DataValue >> 128) == 0, "Value too large");
        require ((nonce >> 32) == 0, "Nonce too large");
        require (delaySeconds > 0, "Delay must be positive");
        
        scheduledTime = now + delaySeconds;
        scheduledValue = DataValue;
        scheduledNonce = nonce;
        hasPendingUpdate = true;
    }
    
    function executeScheduledUpdate() external {
        require(hasPendingUpdate, "No pending update");
        require(now >= scheduledTime, "Update not ready yet");
        
        value = scheduledValue + (scheduledNonce << 192) + (now << 128);
        hasPendingUpdate = false;
        
        if (address(seeker) != address(0)) {
            seeker.poke();
        }
    }
    // === END FALLBACK INJECTION ===

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
        value = DataValue + (nonce << 192) + (now << 128) ;
        if (address(seeker) != address(0)) {
            seeker.poke();
        }
    }
}