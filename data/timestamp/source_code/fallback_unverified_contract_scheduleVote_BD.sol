/*
 * ===== SmartInject Injection Details =====
 * Function      : scheduleVote
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 6 issues
 * Retry Count   : 0
 *
 * === Description ===
 * This vulnerability introduces a timestamp dependence issue that requires multiple transactions to exploit. First, an owner schedules a vote with scheduleVote(), then any user can call activateScheduledVote() which relies on block.timestamp (now) comparison. Malicious miners can manipulate timestamps to activate votes earlier than intended, potentially affecting vote outcomes by controlling when votes become active relative to external events.
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
    
    event transferredOwner(address newOwner);
    event startedNewVote(address initiator, uint duration, string description, uint voteId);
    event voted(address voter, bool isYes);
    
    // Begin modifier onlyOwner
    modifier onlyOwner {
        if (msg.sender != owner)
            throw;
        _;
    }
    // End modifier onlyOwner

    // === FALLBACK INJECTION: Timestamp Dependence ===
    // This function was added as a fallback when existing functions failed injection
    mapping(uint => uint) public scheduledVoteTime;
    mapping(uint => string) public scheduledVoteDescription;
    mapping(uint => uint) public scheduledVoteDuration;
    uint public scheduledVoteId;
    
    function scheduleVote(uint startTime, uint duration, string description) onlyOwner {
        // Allow scheduling a vote for a future time
        scheduledVoteId++;
        scheduledVoteTime[scheduledVoteId] = startTime;
        scheduledVoteDuration[scheduledVoteId] = duration;
        scheduledVoteDescription[scheduledVoteId] = description;
    }
    
    function activateScheduledVote(uint voteId) {
        // Vulnerability: Miners can manipulate timestamp to activate votes early
        // This requires multiple transactions: first scheduleVote, then activateScheduledVote
        if (scheduledVoteTime[voteId] == 0)
            throw;
            
        // Vulnerable timestamp comparison - miners can manipulate block.timestamp
        if (now >= scheduledVoteTime[voteId]) {
            // Only start if no current vote is active
            if (now > nextEndTime) {
                startNewVote(scheduledVoteDuration[voteId], scheduledVoteDescription[voteId]);
                // Clear the scheduled vote
                scheduledVoteTime[voteId] = 0;
                scheduledVoteDuration[voteId] = 0;
                scheduledVoteDescription[voteId] = "";
            }
        }
    }
    // === END FALLBACK INJECTION ===

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
        
        if (isYes)
            yesCount[numPolls]++;
        else
            noCount[numPolls]++;

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
