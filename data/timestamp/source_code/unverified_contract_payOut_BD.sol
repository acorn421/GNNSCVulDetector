/*
 * ===== SmartInject Injection Details =====
 * Function      : payOut
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 6 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Introduced a stateful, multi-transaction Timestamp Dependence vulnerability by implementing a withdrawal delay mechanism. The vulnerability requires:
 * 
 * 1. **State Variables** (assumed to be added to contract): 
 *    - `lastWithdrawalTime`: Tracks when the last successful withdrawal occurred
 *    - `withdrawalRequestTime`: Tracks when withdrawal was requested
 *    - `withdrawalDelay`: Minimum time between withdrawals (24 hours)
 * 
 * 2. **Multi-Transaction Exploitation**:
 *    - **Transaction 1**: Owner calls payOut() for first time, sets lastWithdrawalTime and returns without sending funds
 *    - **Transaction 2**: Owner calls payOut() again before delay expires, only updates withdrawalRequestTime
 *    - **Transaction 3**: Owner calls payOut() after delay period, funds are actually sent
 * 
 * 3. **Vulnerability Mechanics**:
 *    - Miners can manipulate block.timestamp to either prevent legitimate withdrawals by keeping timestamps artificially low
 *    - Miners can accelerate withdrawals by manipulating timestamps to bypass the 24-hour delay
 *    - The withdrawal delay can be bypassed if miners collude to manipulate timestamps across multiple blocks
 *    - Emergency situations where owner needs immediate fund access can be prevented by timestamp manipulation
 * 
 * 4. **Exploitation Scenarios**:
 *    - **Denial of Service**: Miners prevent owner withdrawals by keeping block.timestamp artificially low
 *    - **Bypass Security**: Miners help malicious actors (if owner key is compromised) by manipulating timestamps to bypass the intended security delay
 *    - **Griefing**: Miners can cause unpredictable withdrawal behavior by manipulating timestamps inconsistently across the multi-transaction sequence
 * 
 * The vulnerability is stateful because it depends on persistent state variables that track withdrawal timing across multiple transactions, and it's multi-transaction because the withdrawal process requires at least 2-3 function calls to complete, with the exploitation potential varying depending on timestamp manipulation across these calls.
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
    
    // Added missing variables for withdrawal logic
    uint public lastWithdrawalTime;
    uint public withdrawalRequestTime;
    uint public withdrawalDelay = 1 days;
    
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
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        // Security measure: implement withdrawal delay to prevent rapid fund extraction
        if (lastWithdrawalTime == 0) {
            // First withdrawal attempt - set request time
            lastWithdrawalTime = block.timestamp;
            withdrawalRequestTime = block.timestamp;
            return;
        }
        
        // Check if minimum delay has passed (24 hours)
        if (block.timestamp < lastWithdrawalTime + withdrawalDelay) {
            // Not enough time has passed, update request time
            withdrawalRequestTime = block.timestamp;
            return;
        }
        
        // Proceed with withdrawal
        owner.send(this.balance);
        lastWithdrawalTime = block.timestamp;
        withdrawalRequestTime = 0;
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
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
