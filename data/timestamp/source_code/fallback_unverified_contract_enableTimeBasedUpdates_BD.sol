/*
 * ===== SmartInject Injection Details =====
 * Function      : enableTimeBasedUpdates
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 8 issues
 * Retry Count   : 0
 *
 * === Description ===
 * This vulnerability introduces a stateful, multi-transaction timestamp dependence issue. The vulnerability requires: 1) First calling requestTimedUpdate() to schedule an update at a specific timestamp, 2) Then calling executeScheduledUpdate() when the scheduled time arrives. The vulnerability allows miners to manipulate block timestamps within the update window to potentially execute updates at advantageous times or bypass intended timing constraints. The state persists between transactions through the userUpdateRequests mapping and timeBasedUpdatesEnabled flag.
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
    bool public timeBasedUpdatesEnabled = false;
    uint public updateWindow = 3600; // 1 hour window
    uint public lastScheduledUpdate = 0;
    mapping(address => uint) public userUpdateRequests;
    
    function enableTimeBasedUpdates() public onlyAuth {
        timeBasedUpdatesEnabled = true;
        lastScheduledUpdate = now;
    }
    
    function requestTimedUpdate(uint desiredTimestamp) public {
        require(timeBasedUpdatesEnabled, "Time-based updates not enabled");
        require(desiredTimestamp > now, "Cannot schedule update in the past");
        userUpdateRequests[msg.sender] = desiredTimestamp;
    }
    
    function executeScheduledUpdate(uint DataValue, uint nonce) public {
        require(timeBasedUpdatesEnabled, "Time-based updates not enabled");
        require(userUpdateRequests[msg.sender] > 0, "No update request found");
        require(now >= userUpdateRequests[msg.sender], "Update time not reached");
        require(now <= userUpdateRequests[msg.sender] + updateWindow, "Update window expired");
        
        // Vulnerable: relies on block.timestamp which can be manipulated by miners
        // Multi-transaction: requires requestTimedUpdate() call first, then this call
        require((DataValue >> 128) == 0, "Value too large");
        require((nonce >> 32) == 0, "Nonce too large");
        
        value = DataValue + (nonce << 192) + (now << 128);
        lastScheduledUpdate = now;
        
        // Clear the request
        userUpdateRequests[msg.sender] = 0;
        
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
