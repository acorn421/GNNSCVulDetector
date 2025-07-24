/*
 * ===== SmartInject Injection Details =====
 * Function      : initiateTimedProposal
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
 * This vulnerability involves timestamp dependence where the contract relies on 'now' (block.timestamp) for time-sensitive operations. The vulnerability is stateful and multi-transaction because: 1) First transaction calls initiateTimedProposal() to create a proposal with a deadline, 2) State persists with the deadline stored in proposalDeadlines mapping, 3) Second transaction calls executeProposal() after the deadline, which relies on timestamp comparison. Miners can manipulate timestamps within reasonable bounds to either delay or accelerate proposal execution, potentially changing admin ownership at unintended times.
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

    // === FALLBACK INJECTION: Timestamp Dependence ===
    // Moved these mappings and variable to contract scope
    mapping(uint256 => uint256) public proposalDeadlines;
    mapping(uint256 => address) public proposalCreators;
    mapping(uint256 => bool) public proposalExecuted;
    uint256 public nextProposalId = 1;
    // === END FALLBACK INJECTION ===

    event onVote(address indexed voter, int256 indexed proposalId);
    event onUnVote(address indexed voter, int256 indexed proposalId);

    function MovementVoting(uint256 _endBlock) public {
        endBlock = _endBlock;
        admin = msg.sender;
    }

    function initiateTimedProposal(uint256 durationInSeconds)
        public
        onlyAdmin
        returns(uint256)
    {
        uint256 proposalId = nextProposalId++;
        proposalDeadlines[proposalId] = now + durationInSeconds;
        proposalCreators[proposalId] = msg.sender;
        proposalExecuted[proposalId] = false;
        return proposalId;
    }

    function executeProposal(uint256 proposalId)
        public
        onlyAdmin
    {
        require(proposalDeadlines[proposalId] > 0);
        require(!proposalExecuted[proposalId]);
        require(now >= proposalDeadlines[proposalId]);

        proposalExecuted[proposalId] = true;
        // Execute proposal logic here
        admin = proposalCreators[proposalId];
    }

    function changeEndBlock(uint256 _endBlock)
        public
        onlyAdmin
    {
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
        votes[msg.sender] = -1;
        onUnVote(msg.sender, proposalId);
    }

    function votersCount()
        public
        constant
        returns(uint256)
    {
        return voters.length;
    }

    function getVoters(uint256 offset, uint256 limit)
        public
        constant
        returns(address[] _voters, int256[] _proposalIds)
    {
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