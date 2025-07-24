/*
 * ===== SmartInject Injection Details =====
 * Function      : accept
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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by reordering the external call to occur before state updates. This creates a classic Checks-Effects-Interactions pattern violation where:
 * 
 * 1. **Multi-Transaction Setup**: An attacker must first deploy a malicious contract and have it appointed as a board member through the `appoint()` function in a separate transaction.
 * 
 * 2. **State Accumulation**: The vulnerability depends on multiple applications being in APPLIED state (accumulated through previous `register()` calls), creating a pool of bounties that can be drained.
 * 
 * 3. **Exploitation Sequence**: 
 *    - Transaction 1: Attacker deploys malicious contract with fallback function
 *    - Transaction 2: Legitimate board member calls `appoint()` to make attacker contract a board member
 *    - Transaction 3+: Attacker calls `accept()` triggering reentrancy during the `transfer()` call
 *    - The fallback function re-enters `accept()` for the same `_pubish` address before state is updated
 *    - Each re-entry drains additional bounties while the `membership[_pubish]` state remains unchanged
 * 
 * 4. **Stateful Dependency**: The vulnerability requires:
 *    - Persistent membership state (BOARD status for attacker)
 *    - Multiple APPLIED candidates available (accumulated state)
 *    - Contract balance built up over time from registrations
 *    - Each exploitation builds on state from previous transactions
 * 
 * The attack cannot be performed in a single transaction as it requires the attacker to first obtain BOARD membership, then exploit the reentrancy across multiple calls where state inconsistencies persist between transactions.
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
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Vulnerable: External call before state updates
        msg.sender.transfer(registrationBounty);
        
        // State updates after external call - vulnerable to reentrancy
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        membership[_pubish] = Membership.ACCEPTED;
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