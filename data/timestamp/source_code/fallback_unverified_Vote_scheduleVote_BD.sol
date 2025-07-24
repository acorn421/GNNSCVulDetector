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
 * This vulnerability introduces timestamp dependence where the activation of scheduled votes relies on block.timestamp comparisons. The vulnerability is stateful and multi-transaction because: 1) First transaction calls scheduleVote() to set up the scheduled vote with a future timestamp, 2) Later transaction calls activateScheduledVote() which depends on block.timestamp for activation logic. A malicious miner can manipulate the timestamp within the ~15 minute window to either delay or accelerate vote activation, potentially affecting voting outcomes by controlling when votes become active.
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

    // === FALLBACK INJECTION: Timestamp Dependence ===
    // This function was added as a fallback when existing functions failed injection
    mapping(uint => uint) public scheduledVoteTime;
    mapping(uint => string) public scheduledVoteDescription;
    mapping(uint => bool) public scheduledVoteActive;
    uint public nextScheduledId;

    modifier onlyOwner {
        if (msg.sender != owner)
            throw;
        _;
    }

    function scheduleVote(uint delay, string description) onlyOwner {
        // Schedule a vote to start after a specified delay
        uint scheduleId = nextScheduledId++;
        scheduledVoteTime[scheduleId] = now + delay;
        scheduledVoteDescription[scheduleId] = description;
        scheduledVoteActive[scheduleId] = true;
    }

    function activateScheduledVote(uint scheduleId) {
        // Activate a scheduled vote if enough time has passed
        if (!scheduledVoteActive[scheduleId])
            throw;

        // Vulnerable: Uses block.timestamp for time comparison
        // Can be manipulated by miners within ~900 second window
        if (now >= scheduledVoteTime[scheduleId]) {
            // Only start if no current vote is active
            if (now > nextEndTime) {
                scheduledVoteActive[scheduleId] = false;
                startNewVote(1 hours, scheduledVoteDescription[scheduleId]);
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
