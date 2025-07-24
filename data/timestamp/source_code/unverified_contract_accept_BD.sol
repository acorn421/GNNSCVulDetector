/*
 * ===== SmartInject Injection Details =====
 * Function      : accept
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
 * Introduced a timestamp dependence vulnerability by making the bounty payment dependent on block.timestamp calculations. The vulnerability requires two separate transactions: 1) First, an application must be registered (via register function) which stores the application timestamp, 2) Then, the accept function uses block.timestamp to calculate time elapsed and determine bounty amount. This creates a multi-transaction vulnerability where miners can manipulate block timestamps to maximize bounty payouts. The vulnerability is stateful because it depends on the applicationTimestamps mapping that persists between transactions, and the time calculation creates different outcomes based on when the acceptance occurs relative to the application timestamp.
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

    // Added mapping for application timestamps
    mapping (address => uint256) public applicationTimestamps;

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
        applicationTimestamps[_pubish] = block.timestamp; // Record application timestamp
        PubRegistered(_pubish);
    }

    function accept(address _pubish)
    external {
        assert(membership[msg.sender] >= Membership.BOARD);
        assert(membership[_pubish] == Membership.APPLIED);
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        
        // Time-based bounty calculation - vulnerability injection
        uint256 timeElapsed = block.timestamp - applicationTimestamps[_pubish];
        uint256 adjustedBounty = registrationBounty;
        
        // Bounty increases if accepted within "premium" time window
        if (timeElapsed >= 1 hours && timeElapsed <= 24 hours) {
            adjustedBounty = registrationBounty + (registrationBounty * 20 / 100); // 20% bonus
        }
        
        membership[_pubish] = Membership.ACCEPTED;
        msg.sender.transfer(adjustedBounty);
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
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
