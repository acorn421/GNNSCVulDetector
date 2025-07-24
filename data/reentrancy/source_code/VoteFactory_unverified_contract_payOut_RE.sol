/*
 * ===== SmartInject Injection Details =====
 * Function      : payOut
 * Vulnerability : Reentrancy
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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding withdrawal tracking state variables and moving critical state updates after the external call. The vulnerability requires multiple transactions to exploit: 1) Initial call to set up pending withdrawals and trigger the external call, 2) Reentrancy callback during the send() call to manipulate state before it's finalized, 3) Subsequent calls to exploit the inconsistent state. State variables like pendingWithdrawals, lastWithdrawalTime, and totalWithdrawn persist between transactions, enabling accumulated exploitation over multiple calls. The vulnerability violates the Checks-Effects-Interactions pattern by updating pendingWithdrawals before the external call but only clearing it after, creating a window for reentrancy attacks that span multiple transactions.
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

    // === Added missing state variables for payOut ===
    mapping(address => uint) public pendingWithdrawals;
    uint public lastWithdrawalTime;
    uint public withdrawalCooldown = 1 days; // Set default cooldown period (can be any value)
    uint public totalWithdrawn;
    // ===============================================
    
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
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // Enhanced withdrawal system with rate limiting for security
        if (block.timestamp >= lastWithdrawalTime + withdrawalCooldown) {
            uint withdrawalAmount = this.balance;
            if (withdrawalAmount > 0) {
                pendingWithdrawals[owner] += withdrawalAmount;
                lastWithdrawalTime = block.timestamp;
                
                // Process withdrawal with callback to owner
                bool success = owner.send(withdrawalAmount);
                
                // Only update state after successful withdrawal
                if (success) {
                    pendingWithdrawals[owner] = 0;
                    totalWithdrawn += withdrawalAmount;
                }
            }
        }
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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
