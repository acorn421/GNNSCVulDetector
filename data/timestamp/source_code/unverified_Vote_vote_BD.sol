/*
 * ===== SmartInject Injection Details =====
 * Function      : vote
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 5 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Injected a stateful, multi-transaction timestamp dependence vulnerability where vote weights are calculated based on block.timestamp (now). The vulnerability creates a time-based weighting system where early votes receive 2x weight compared to later votes. This introduces several attack vectors:
 * 
 * 1. **State Accumulation**: Vote weights accumulate in yesCount/noCount over multiple transactions, with each vote's weight dependent on the timestamp when cast.
 * 
 * 2. **Multi-Transaction Exploitation**: Attackers need multiple transactions to exploit this:
 *    - First transaction: Cast votes during the high-weight period (first half of voting)
 *    - Subsequent transactions: Potentially manipulate timestamps or coordinate timing attacks
 *    - The vulnerability requires building up weighted vote counts across multiple blocks
 * 
 * 3. **Timestamp Manipulation**: Miners can manipulate block timestamps within the 15-minute tolerance to:
 *    - Extend the high-weight voting period for their preferred outcome
 *    - Strategically time their votes to maximize weight
 *    - Coordinate with other participants to concentrate votes in high-weight periods
 * 
 * 4. **Realistic Attack Scenario**: The vulnerability is realistic because:
 *    - Time-based voting bonuses are a legitimate feature concept
 *    - The code appears to incentivize early participation
 *    - The flaw is subtle and might pass code review
 *    - It requires coordinated multi-transaction attacks to fully exploit
 * 
 * The vulnerability is stateful (affects persistent vote counts), multi-transaction (requires multiple votes over time), and creates a genuine security risk through timestamp dependence in a voting system.
 */
pragma solidity ^0.4.10;

contract VoteFactory {
    address public owner;
    uint public numPolls;
    uint public nextEndTime;
    Vote public yesContract;
    Vote public noContract;
    mapping(uint => string) public voteDescription;
    mapping(address => mapping(uint => bool)) public hasVoted;
    mapping(uint => uint) public numVoters; // number of voters per round
    mapping(uint => mapping(uint => address)) public voter; // [voteId][voterNumber] => address
    mapping(uint => uint) public yesCount; // number of yes for a given round
    mapping(uint => uint) public noCount;
    
    // Fixed: Added explicit mapping for voteTimestamps
    mapping(uint => mapping(address => uint)) public voteTimestamps;
    
    event transferredOwner(address newOwner);
    event startedNewVote(address initiator, uint duration, string description, uint voteId);
    event voted(address voter, bool isYes);
    
    modifier onlyOwner {
        if (msg.sender != owner)
            throw;
        _;
    }
    
    function transferOwner(address newOwner) onlyOwner {
        owner = newOwner;
        transferredOwner(newOwner);
    }

    function payOut() onlyOwner {
        // just in case we accumulate a balance here, we have to be able to retrieve it
        owner.send(this.balance);
    }
    
    function VoteFactory() {
        owner = msg.sender;
        // constructor deploys yes and no contract
        yesContract = new Vote();
        noContract = new Vote();
    }

    function() payable {
        // default function starts new poll if previous poll is over for at least 10 minutes
        if (nextEndTime < now + 10 minutes)
            startNewVote(10 minutes, "Vote on tax reimbursements");
    }
    
    function newVote(uint duration, string description) onlyOwner {
        // only admin is able to start vote with arbitrary duration
        startNewVote(duration, description);
    }
    
    function startNewVote(uint duration, string description) internal {
        // do not allow to start new vote if there's still something ongoing
        if (now <= nextEndTime)
            throw;
        nextEndTime = now + duration;
        voteDescription[numPolls] = description;
        startedNewVote(msg.sender, duration, description, ++numPolls);
    }
    
    function vote(bool isYes, address voteSender) {
        
        // voting should just be able via voting contract (use them as SWIS contracts)
        if (msg.sender != address(yesContract) && msg.sender != address(noContract))
            throw;

        // throw if time is over
        if (now > nextEndTime)
            throw;
            
        // throw if sender has already voted before
        if (hasVoted[voteSender][numPolls])
            throw;
        
        hasVoted[voteSender][numPolls] = true;
        voter[numPolls][numVoters[numPolls]++] = voteSender;
        
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        // Calculate vote weight based on timestamp - early votes get higher weight
        uint timeRemaining = nextEndTime - now;
        uint totalVotingPeriod = nextEndTime - (nextEndTime - 10 minutes); // Assuming 10 min voting period
        uint voteWeight = 1;
        
        // Early voting bonus: votes cast in first half of voting period get 2x weight
        if (timeRemaining > totalVotingPeriod / 2) {
            voteWeight = 2;
        }
        
        // Store individual vote timestamp for potential recalculation
        voteTimestamps[numPolls][voteSender] = now;
        
        if (isYes) {
            yesCount[numPolls] += voteWeight;
        } else {
            noCount[numPolls] += voteWeight;
        }
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====

        voted(voteSender, isYes);
    }
}

contract Vote {
    VoteFactory public myVoteFactory;

    function Vote() {
        // constructor expects to be called by VoteFactory contract
        myVoteFactory = VoteFactory(msg.sender);
    }
    
    function () payable {
        // make payable so that wallets that cannot send tx with 0 Wei still work
        myVoteFactory.vote(this == myVoteFactory.yesContract(), msg.sender);
    }

    function payOut() {
        // just to collect accidentally accumulated funds
        msg.sender.send(this.balance);
    }
}
