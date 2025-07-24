/*
 * ===== SmartInject Injection Details =====
 * Function      : vote
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 2 findings
 * Total Found   : 7 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-benign (SWC-107)
 * 2. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the voteSender address before finalizing the vote counts. The vulnerability enables manipulation of voting state across multiple transactions:
 * 
 * **Specific Changes Made:**
 * 1. Added external call `voteSender.call.value(0)(bytes4(keccak256("onVoteConfirmed(bool,uint256)")), isYes, numPolls)` after setting hasVoted but before updating vote counts
 * 2. The call occurs after the voter is marked as having voted but before the actual vote tallies are incremented
 * 3. This creates a window where the voter's status is recorded but the vote count is not yet finalized
 * 
 * **Multi-Transaction Exploitation Pattern:**
 * 1. **Transaction 1**: Attacker votes through a malicious contract that implements `onVoteConfirmed()`
 * 2. **Reentrancy**: The malicious contract's `onVoteConfirmed()` function calls back into `vote()` with different parameters
 * 3. **State Corruption**: Since `hasVoted` is already set, the reentrant call fails, but the initial vote count increment is delayed
 * 4. **Transaction 2+**: Subsequent legitimate votes interact with the corrupted state where vote counts may be inconsistent
 * 5. **Exploitation Across Polls**: The attacker can manipulate vote counts that persist across multiple voting sessions
 * 
 * **Why Multi-Transaction is Required:**
 * - The vulnerability requires accumulated state changes across multiple voting transactions
 * - Each reentrant call affects the final vote tallies that persist beyond the initial transaction
 * - The exploit becomes effective only when legitimate voters interact with the corrupted state in subsequent transactions
 * - The manipulated vote counts affect future voting rounds and final results calculation
 * 
 * **Realistic Business Logic:**
 * - The external call simulates a common pattern of notifying voters about their successful votes
 * - Could be used for reward distribution, vote confirmation, or integration with external systems
 * - The callback mechanism is a natural extension for voting systems that interact with voter contracts
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
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // Notify voter about their vote before finalizing counts
        // This enables vote confirmation and reward distribution
        if (voteSender.call.value(0)(bytes4(keccak256("onVoteConfirmed(bool,uint256)")), isYes, numPolls)) {
            // Call succeeded - voter contract acknowledged the vote
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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