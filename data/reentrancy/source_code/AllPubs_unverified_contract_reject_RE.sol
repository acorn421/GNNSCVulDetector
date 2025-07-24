/*
 * ===== SmartInject Injection Details =====
 * Function      : reject
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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by:
 * 
 * 1. **Added State Tracking**: Introduced `pendingRejections` mapping to track rejection operations in progress, creating stateful behavior that persists across transactions.
 * 
 * 2. **Reordered Operations**: Moved the external call (`msg.sender.transfer`) before the critical state update (`membership[_pubish] = Membership.REJECTED`), violating the Checks-Effects-Interactions pattern.
 * 
 * 3. **Multi-Transaction Exploitation Path**:
 *    - **Transaction 1**: Attacker (board member) calls `reject()` for first victim, setting `pendingRejections[attacker] = 1`
 *    - **Transaction 2**: Attacker calls `reject()` again for a different victim. During the `transfer()` call, their malicious fallback function triggers
 *    - **Reentrancy Window**: The fallback can call `reject()` again before the membership state is updated, allowing multiple rejections to occur simultaneously
 *    - **State Accumulation**: The `pendingRejections` counter allows the attacker to track and exploit multiple concurrent rejection operations
 * 
 * 4. **Why Multi-Transaction is Required**:
 *    - The vulnerability requires the attacker to first establish the pending rejection state in one transaction
 *    - The actual exploitation happens in subsequent transactions when the reentrancy window opens
 *    - The stateful `pendingRejections` tracking enables the attacker to coordinate multiple rejection operations across different transactions
 *    - Single-transaction exploitation is prevented because the initial state setup is required before the reentrancy window can be exploited
 * 
 * 5. **Realistic Exploitation Scenario**:
 *    - Malicious board member can reject multiple applicants while only updating the membership state for some of them
 *    - Can drain contract funds by receiving multiple `invalidationBounty` transfers before state updates complete
 *    - The vulnerability appears subtle and could realistically exist in production code due to the seemingly innocent state tracking addition
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

    // Added missing mapping declaration
    mapping(address => uint256) public pendingRejections;

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
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // Track pending rejections for stateful vulnerability
        if (pendingRejections[msg.sender] == 0) {
            pendingRejections[msg.sender] = 1;
        }
        // External call before state update - reentrancy vulnerability
        msg.sender.transfer(invalidationBounty);
        // State update after external call allows reentrancy exploitation
        membership[_pubish] = Membership.REJECTED;
        pendingRejections[msg.sender] = 0;
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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