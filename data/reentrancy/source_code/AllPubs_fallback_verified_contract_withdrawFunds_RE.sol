/*
 * ===== SmartInject Injection Details =====
 * Function      : withdrawFunds
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 1 findings
 * Total Found   : 2 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-eth (SWC-107)
 *
 * === Description ===
 * Multi-transaction reentrancy vulnerability where an attacker can: 1) First call requestWithdrawal() to set up pending withdrawal state, 2) Then call withdrawFunds() which makes external call before clearing the pending amount, 3) The external call can reenter withdrawFunds() while pendingWithdrawals[attacker] is still non-zero, allowing multiple withdrawals of the same amount. This requires multiple transactions and stateful interaction between requestWithdrawal() and withdrawFunds() functions.
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

    // === FALLBACK INJECTION: Reentrancy ===
    // This function was added as a fallback when existing functions failed injection
    // Mapping to track withdrawal requests
    mapping (address => uint256) public pendingWithdrawals;
    
    // Mapping for membership (needs to be defined before usage in functions)
    mapping (address => Membership) public membership;

    // Request withdrawal of accumulated registration bounties
    function requestWithdrawal(uint256 _amount) 
    external {
        assert(membership[msg.sender] >= Membership.BOARD);
        assert(_amount > 0);
        assert(address(this).balance >= _amount);
        
        pendingWithdrawals[msg.sender] += _amount;
        
        // State change happens after external call in withdrawFunds
    }
    
    // Withdraw requested funds - vulnerable to reentrancy
    function withdrawFunds()
    external {
        assert(membership[msg.sender] >= Membership.BOARD);
        uint256 amount = pendingWithdrawals[msg.sender];
        assert(amount > 0);
        
        // VULNERABILITY: External call before state change
        // This allows reentrancy attacks across multiple transactions
        msg.sender.call.value(amount)();
        
        // State change happens after external call
        pendingWithdrawals[msg.sender] = 0;
    }
    // === END FALLBACK INJECTION ===

    // please do not trust REJECTED abis
    mapping (address => string) public abis;
    address[] public pubs;

    function AllPubs() public {
        membership[msg.sender] = Membership.SOURCE;
    }

    event PubRegistered(address location);
    event PubAccepted(address location);
    event PubRejected(address location, string reason);

    function pubCount() public view returns (uint256) {
        return pubs.length;
    }

    function register(address _pubish, string _abi) external payable {
        assert(msg.value == registrationBounty);
        assert(membership[_pubish] <= Membership.REJECTED);
        membership[_pubish] = Membership.APPLIED;
        abis[_pubish] = _abi;
        PubRegistered(_pubish);
    }

    function accept(address _pubish) external {
        assert(membership[msg.sender] >= Membership.BOARD);
        assert(membership[_pubish] == Membership.APPLIED);
        membership[_pubish] = Membership.ACCEPTED;
        msg.sender.transfer(registrationBounty);
        pubs.push(_pubish);
        PubAccepted(_pubish);
    }

    function reject(address _pubish, string _reason) external {
        assert(membership[msg.sender] >= Membership.BOARD);
        assert(membership[_pubish] == Membership.APPLIED);
        membership[_pubish] = Membership.REJECTED;
        msg.sender.transfer(invalidationBounty);
        PubRejected(_pubish, _reason);
    }

    event NewBoardMember(address _boardMember);

    function appoint(address _delegate) external {
        assert(membership[msg.sender] >= Membership.BOARD);
        assert(membership[_delegate] == Membership.UNCONTACTED);
        membership[_delegate] = Membership.BOARD;
        NewBoardMember(_delegate);
    }
}
