/*
 * ===== SmartInject Injection Details =====
 * Function      : scheduleMaintenance
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 1 issues
 * Retry Count   : 0
 *
 * === Description ===
 * This vulnerability introduces timestamp dependence where miners can manipulate block.timestamp to either delay or accelerate maintenance execution. The vulnerability is stateful and multi-transaction because: 1) First transaction schedules maintenance with a future timestamp, 2) Second transaction executes maintenance but relies on block.timestamp comparison, 3) State persists between transactions (maintenanceScheduled, maintenanceScheduledTime), 4) Miners can manipulate timestamps within certain bounds to execute maintenance earlier than intended and claim rewards prematurely.
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
    } // <-- Fixed: added missing closing parenthesis

    // === FALLBACK INJECTION: Timestamp Dependence ===
    // This function was added as a fallback when existing functions failed injection
    // Maintenance scheduling for pub registry
    uint256 public maintenanceScheduledTime;
    bool public maintenanceScheduled = false;
    address public maintenanceScheduler;

    event MaintenanceScheduled(uint256 scheduledTime, address scheduler);
    event MaintenanceExecuted(address executor);

    function scheduleMaintenance(uint256 _delayHours)
    external {
        assert(membership[msg.sender] >= Membership.BOARD);
        assert(!maintenanceScheduled);

        // Vulnerable: using block.timestamp for time-sensitive operations
        maintenanceScheduledTime = block.timestamp + (_delayHours * 1 hours);
        maintenanceScheduled = true;
        maintenanceScheduler = msg.sender;

        MaintenanceScheduled(maintenanceScheduledTime, msg.sender);
    }

    function executeMaintenance()
    external {
        assert(maintenanceScheduled);
        // Vulnerable: timestamp dependence - miners can manipulate block.timestamp
        assert(block.timestamp >= maintenanceScheduledTime);
        assert(membership[msg.sender] >= Membership.BOARD);

        // Reset maintenance state
        maintenanceScheduled = false;
        maintenanceScheduledTime = 0;

        // Transfer accumulated bounties to maintenance executor
        uint256 maintenanceReward = this.balance / 10; // 10% of contract balance
        msg.sender.transfer(maintenanceReward);

        MaintenanceExecuted(msg.sender);
    }
    // === END FALLBACK INJECTION ===

    mapping (address => Membership) public membership;
    // please do not trust REJECTED abis
    mapping (address => string) public abis;
    address[] public pubs;

    function AllPubs()
    public {
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
        membership[_pubish] = Membership.REJECTED;
        msg.sender.transfer(invalidationBounty);
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
