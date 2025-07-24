/*
 * ===== SmartInject Injection Details =====
 * Function      : poke
 * Vulnerability : Reentrancy
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 0 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability in the poke() function. The vulnerability requires multiple transactions to exploit:
 * 
 * **Multi-Transaction Exploitation Pattern:**
 * 1. **Transaction 1-4**: Attacker calls poke() 4 times to accumulate 4 ether in pendingRewards
 * 2. **Transaction 5**: Attacker calls poke() with a malicious contract that implements onRewardReady()
 * 3. **During Transaction 5**: When the external call to onRewardReady() occurs, the attacker's contract can re-enter poke() before the state is updated
 * 4. **Reentrancy Exploitation**: The re-entrant call sees pendingRewards[attacker] still at 5 ether and totalPendingRewards unchanged, allowing multiple reward claims
 * 
 * **State Persistence Requirements:**
 * - pendingRewards mapping tracks accumulated rewards across multiple transactions
 * - processingReward mapping prevents simple single-transaction reentrancy
 * - totalPendingRewards maintains global state that can be manipulated
 * - rewardQueue tracks active participants across transactions
 * 
 * **Why Multi-Transaction is Required:**
 * - The vulnerability requires building up pendingRewards to >= 5 ether over multiple calls
 * - Single transaction reentrancy is blocked by the processingReward flag
 * - However, the external call occurs before state cleanup, allowing manipulation of the accumulated state
 * - The attacker must first accumulate rewards over multiple transactions before the final exploit transaction
 * 
 * **Realistic Scenario:**
 * This represents a realistic reward/notification system where participants accumulate rewards over time and get notified when thresholds are met. The vulnerability arises from the classic reentrancy pattern of external calls before state updates, but requires prior state accumulation to be exploitable.
 */
pragma solidity ^0.4.24;

// Searcher is an interface for contracts that want to be notified of incoming data
//
contract Searcher {

    // poke is called when new data arrives
    //
    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
    mapping(address => uint) public pendingRewards;
    mapping(address => bool) public processingReward;
    uint public totalPendingRewards;
    address[] public rewardQueue;

    function poke() public {
        // Add caller to reward queue if not already pending
        if (pendingRewards[msg.sender] == 0) {
            rewardQueue.push(msg.sender);
        }
        
        // Accumulate rewards for active participants
        pendingRewards[msg.sender] += 1 ether;
        totalPendingRewards += 1 ether;
        
        // Process rewards if caller has sufficient accumulated rewards
        if (pendingRewards[msg.sender] >= 5 ether && !processingReward[msg.sender]) {
            processingReward[msg.sender] = true;
            
            // External call to notify reward processor contract
            if (isContract(msg.sender)) {
                // Vulnerable: External call before state update
                (bool success, ) = msg.sender.call(abi.encodeWithSignature("onRewardReady(uint256)", pendingRewards[msg.sender]));
                require(success, "Reward notification failed");
            }
            
            // State update after external call - VULNERABILITY
            totalPendingRewards -= pendingRewards[msg.sender];
            pendingRewards[msg.sender] = 0;
            processingReward[msg.sender] = false;
            
            // Remove from queue
            for (uint i = 0; i < rewardQueue.length; i++) {
                if (rewardQueue[i] == msg.sender) {
                    rewardQueue[i] = rewardQueue[rewardQueue.length - 1];
                    rewardQueue.length--;
                    break;
                }
            }
        }
    }

    // In Solidity 0.4.x, address.code does not exist. Use extcodesize to detect contracts
    function isContract(address _addr) internal view returns (bool) {
        uint256 size;
        assembly { size := extcodesize(_addr) }
        return size > 0;
    }
// ===== SMARTINJECT: Reentrancy VULNERABILITY END =====

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
        value = DataValue + (nonce << 192) + (now << 128) ;
        if (address(seeker) != address(0)) {
            seeker.poke();
        }
    }
}
