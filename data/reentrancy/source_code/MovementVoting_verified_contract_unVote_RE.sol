/*
 * ===== SmartInject Injection Details =====
 * Function      : unVote
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 2 findings
 * Total Found   : 2 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to a user-controlled voteTracker contract before state updates. The vulnerability requires multiple transactions to exploit: first to set up the voteTracker contract, then to trigger the reentrancy attack during unVote. The external call occurs after the vote validity check but before the state update (votes[msg.sender] = -1), allowing reentrancy to bypass the checks-effects-interactions pattern. An attacker can: 1) Set up malicious voteTracker contract in transaction 1, 2) Call unVote() in transaction 2 which triggers external call, 3) The malicious contract can reenter unVote() seeing the original vote state before it's updated, allowing double-processing or state corruption that persists across transactions.
 */
/**
  * The Movement
  * Decentralized Autonomous Organization
  */
  
pragma solidity ^0.4.18;

contract MovementVoting {
    mapping(address => int256) public votes;
    address[] public voters;
    uint256 public endBlock;
    address public admin;
    
    // Declare the voteTracker variable and the interface
    VoteTracker public voteTracker;
    
    event onVote(address indexed voter, int256 indexed proposalId);
    event onUnVote(address indexed voter, int256 indexed proposalId);

    // Use constructor keyword instead of function name
    constructor(uint256 _endBlock) public {
        endBlock = _endBlock;
        admin = msg.sender;
    }

    function changeEndBlock(uint256 _endBlock)
    onlyAdmin public {
        endBlock = _endBlock;
    }

    function vote(int256 proposalId) public {
        require(msg.sender != address(0));
        require(proposalId > 0);
        require(endBlock == 0 || block.number <= endBlock);
        if (votes[msg.sender] == 0) {
            voters.push(msg.sender);
        }

        votes[msg.sender] = proposalId;

        onVote(msg.sender, proposalId);
    }

    function unVote() public {
        require(msg.sender != address(0));
        require(votes[msg.sender] > 0);
        int256 proposalId = votes[msg.sender];
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Notify external vote tracking contract of unvote
        if (address(voteTracker) != address(0)) {
            voteTracker.onUserUnvote(msg.sender, proposalId);
        }
        
        votes[msg.sender] = -1;
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        onUnVote(msg.sender, proposalId);
    }

    function votersCount() public constant returns(uint256) {
        return voters.length;
    }

    function getVoters(uint256 offset, uint256 limit) public constant returns(address[] _voters, int256[] _proposalIds) {
        if (offset < voters.length) {
            uint256 resultLength = limit;
            uint256 index = 0;

            if (voters.length - offset < limit) {
                resultLength = voters.length - offset;
            }

            _voters = new address[](resultLength);
            _proposalIds = new int256[](resultLength);

            for(uint256 i = offset; i < offset + resultLength; i++) {
                _voters[index] = voters[i];
                _proposalIds[index] = votes[voters[i]];
                index++;
            }

            return (_voters, _proposalIds);
        }
    }

    modifier onlyAdmin() {
        if (msg.sender != admin) revert();
        _;
    }
}

// Declared outside the contract for clarity
interface VoteTracker {
    function onUserUnvote(address voter, int256 proposalId) external;
}