/*
 * ===== SmartInject Injection Details =====
 * Function      : vote
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 3 findings
 * Total Found   : 8 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-benign (SWC-107)
 * 3. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the voter's address before updating the hasVoted state. The vulnerability requires multiple transactions to exploit:
 * 
 * **Multi-Transaction Exploitation Process:**
 * 
 * 1. **Transaction 1 (Setup)**: Legitimate voters participate to build up numVoters[numPolls] > 0, establishing the necessary state for the vulnerability to trigger.
 * 
 * 2. **Transaction 2 (Initial Attack)**: Attacker calls vote() through voting contract, which triggers the external call to attacker's contract via `voteSender.call()` before `hasVoted[voteSender][numPolls] = true` is executed.
 * 
 * 3. **Transaction 3+ (Reentrancy Chain)**: In the attacker's `onVoteReward()` callback, they can call vote() again since `hasVoted` hasn't been set yet. This creates a reentrant call that bypasses the duplicate voting check.
 * 
 * 4. **State Accumulation**: Each reentrant call increments vote counts (yesCount/noCount) and voter arrays while the `hasVoted` flag remains false until the original call completes.
 * 
 * **Why Multi-Transaction is Required:**
 * - The vulnerability depends on accumulated state from previous legitimate voting transactions (numVoters[numPolls] > 0)
 * - The attack requires building up this state across multiple transactions from different participants
 * - The exploit cannot work in isolation - it needs the voting system's accumulated state to trigger the external call condition
 * - Each exploitation cycle requires separate transactions to build up fraudulent vote counts over time
 * 
 * **Realistic Attack Scenario:**
 * An attacker would deploy a malicious contract, wait for legitimate voting activity to accumulate, then exploit the reentrancy to cast multiple votes in a single transaction while appearing as a single voter, bypassing the one-vote-per-address limitation.
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
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // NEW: Reward distribution for active voters before updating vote status
        // This external call creates a reentrancy window before state updates
        if (numVoters[numPolls] > 0) {
            // Call external reward contract to distribute voting incentives
            // This allows reentrant calls before hasVoted is set to true
            bool success = voteSender.call(bytes4(keccak256("onVoteReward(uint256,bool)")), numPolls, isYes);
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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