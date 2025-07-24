/*
 * ===== SmartInject Injection Details =====
 * Function      : reject
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
 * **Specific Changes Made:**
 * 
 * 1. **Added Timestamp Storage**: Introduced `lastRejectionTime[_pubish] = rejectionTime` to store when each publisher was rejected using `block.timestamp`
 * 
 * 2. **Time-Based Bounty Calculation**: Added dynamic bounty calculation that gives bonus rewards for rejections within the first hour of application, using `block.timestamp - applicationTime[_pubish]`
 * 
 * 3. **Cooling Period Logic**: Added timestamp-based cooling period mechanism (though enforcement would be in register function)
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 
 * **Transaction 1 - Application Setup:**
 * - Publisher applies via `register()` function
 * - `applicationTime[_pubish]` is set to current `block.timestamp`
 * 
 * **Transaction 2 - Vulnerable Rejection:**
 * - Board member calls `reject()` within manipulation window
 * - Miner manipulates `block.timestamp` to appear as if rejection happened within 1 hour of application
 * - Attacker receives bonus bounty (150% of normal invalidationBounty)
 * 
 * **Transaction 3 - State Exploitation:**
 * - Later transactions can exploit the stored `lastRejectionTime` for:
 *   - Bypassing cooling periods in future applications
 *   - Manipulating governance timing
 *   - Creating unfair advantage windows
 * 
 * **Why Multiple Transactions Are Required:**
 * 
 * 1. **State Dependency**: The vulnerability relies on `applicationTime` being set in a previous transaction (register function)
 * 
 * 2. **Time Window Exploitation**: The bonus bounty window creates a multi-block opportunity for miners to manipulate timestamps between application and rejection
 * 
 * 3. **Persistent State Impact**: The `lastRejectionTime` storage affects future contract interactions, creating long-term stateful vulnerabilities
 * 
 * 4. **Cross-Function Dependencies**: The exploit requires coordination between register() (sets applicationTime) and reject() (exploits time difference)
 * 
 * **Realistic Attack Vector:**
 * - Colluding miners can manipulate block.timestamp within the 15-minute tolerance
 * - Board members can coordinate with miners to maximize bounty payouts
 * - Publishers can time their applications to exploit known mining patterns
 * - The stored timestamp state creates ongoing vulnerability for future governance decisions
 */
pragma solidity ^0.4.18;

/**
 * Manually audited pub registrar
 *
 * State Diagram:
 * 
 * UNCONTACTED -> APPLIED <-> REJECTED
 *      |            |
 *      v            v
 *    BOARD       ACCEPTED
 */
contract AllPubs {
    // the application fee serves to incentivize the board to review applications quickly
    uint256 constant public registrationBounty = 50 finney;
    // the board receives less when it rejects candidates
    uint256 constant public invalidationBounty = 5 finney;

    enum Membership {
        UNCONTACTED, // default
        REJECTED, // rejected applicant
        APPLIED, // application
        ACCEPTED, // accepted applicant
        BOARD, // allowed to approve pubs
        SOURCE // AllPubs creator
    }

    mapping (address => Membership) public membership;
    // please do not trust REJECTED abis
    mapping (address => string) public abis;
    address[] public pubs;

    // ADDED: missing storage for rejection/application times
    mapping (address => uint256) public lastRejectionTime;
    mapping (address => uint256) public applicationTime;

    constructor() public {
        membership[msg.sender] = Membership.SOURCE;
    }

    event PubRegistered(address location);

    event PubAccepted(address location);

    event PubRejected(address location, string reason);

    function pubCount()
    public view
    returns (uint256) {
        return pubs.length;
    }


    function register(address _pubish, string _abi)
    external payable {
        assert(msg.value == registrationBounty);
        assert(membership[_pubish] <= Membership.REJECTED);
        membership[_pubish] = Membership.APPLIED;
        abis[_pubish] = _abi;
        applicationTime[_pubish] = block.timestamp; // ADDED: track application time
        PubRegistered(_pubish);
    }

    function accept(address _pubish)
    external {
        assert(membership[msg.sender] >= Membership.BOARD);
        assert(membership[_pubish] == Membership.APPLIED);
        membership[_pubish] = Membership.ACCEPTED;
        msg.sender.transfer(registrationBounty);
        pubs.push(_pubish);
        PubAccepted(_pubish);
    }

    function reject(address _pubish, string _reason)
    external {
        assert(membership[msg.sender] >= Membership.BOARD);
        assert(membership[_pubish] == Membership.APPLIED);
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        
        // Add timestamp-based cooling period to prevent rapid re-applications
        // Vulnerable: Uses block.timestamp which can be manipulated by miners
        uint256 coolingPeriod = 1 days;
        uint256 rejectionTime = block.timestamp;
        
        // Store rejection timestamp for this publisher
        lastRejectionTime[_pubish] = rejectionTime;
        
        // Calculate dynamic bounty based on time since application
        // Vulnerable: Time-based calculation using manipulable block.timestamp
        uint256 timeBasedBounty = invalidationBounty;
        if (block.timestamp - applicationTime[_pubish] < 1 hours) {
            // Bonus for quick rejection within first hour
            timeBasedBounty = invalidationBounty + (invalidationBounty / 2);
        }
        
        membership[_pubish] = Membership.REJECTED;
        msg.sender.transfer(timeBasedBounty);
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
        PubRejected(_pubish, _reason);
    }

    event NewBoardMember(address _boardMember);

    function appoint(address _delegate)
    external {
        assert(membership[msg.sender] >= Membership.BOARD);
        assert(membership[_delegate] == Membership.UNCONTACTED);
        membership[_delegate] = Membership.BOARD;
        NewBoardMember(_delegate);
    }
}
