/*
 * ===== SmartInject Injection Details =====
 * Function      : claimDelegatedVotes
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 2 issues
 * Retry Count   : 0
 *
 * === Description ===
 * This vulnerability introduces timestamp dependence in a multi-transaction voting claim system. The exploit requires: 1) Setting a voting deadline, 2) Claiming delegated votes near the deadline, and 3) Finalizing the claim after a time delay. Miners can manipulate timestamps to either extend deadlines or reduce waiting periods, allowing them to claim votes inappropriately or bypass time-based restrictions across multiple transactions.
 */
pragma solidity ^0.4.19;

// DELEGATION SC

// (c) SecureVote 2018

// Released under MIT licence

contract SVDelegation {

    address public owner;

    struct Delegation {
        uint256 thisDelegationId;
        address dlgt;
        uint256 setAtBlock;
        uint256 prevDelegation;
    }

    // === FALLBACK INJECTION: Timestamp Dependence ===
    // New state variables for voting claims
    mapping (address => uint256) public votingDeadlines;
    mapping (address => uint256) public lastClaimTime;
    mapping (address => bool) public hasActiveClaim;
    
    event VotingDeadlineSet(address voter, uint256 deadline);
    event VotesClaimed(address claimer, address voter, uint256 timestamp);
    
    // Function to set voting deadline for a specific voter
    function setVotingDeadline(address voter, uint256 hoursFromNow) public {
        require(hoursFromNow > 0 && hoursFromNow <= 168); // Max 1 week
        votingDeadlines[voter] = now + (hoursFromNow * 1 hours);
        VotingDeadlineSet(voter, votingDeadlines[voter]);
    }
    
    // Function to claim delegated votes - vulnerable to timestamp manipulation
    function claimDelegatedVotes(address voter) public {
        require(votingDeadlines[voter] > 0);
        require(!hasActiveClaim[voter]);
        
        // Vulnerable: Using 'now' for time-sensitive operations
        // Miners can manipulate timestamp within ~15 minutes
        if (now >= votingDeadlines[voter]) {
            hasActiveClaim[voter] = true;
            lastClaimTime[voter] = now;
            VotesClaimed(msg.sender, voter, now);
        }
    }
    
    // Function to finalize claim - requires multiple transactions
    function finalizeClaim(address voter) public {
        require(hasActiveClaim[voter]);
        require(lastClaimTime[voter] > 0);
        
        // Vulnerable: Another timestamp dependency
        // Must wait at least 1 hour after claiming, but miners can manipulate
        require(now >= lastClaimTime[voter] + 1 hours);
        
        // Reset state after finalization
        hasActiveClaim[voter] = false;
        votingDeadlines[voter] = 0;
        lastClaimTime[voter] = 0;
    }
    // === END FALLBACK INJECTION ===

    mapping (address => mapping (address => Delegation)) tokenDlgts;
    mapping (address => Delegation) globalDlgts;

    mapping (uint256 => Delegation) public historicalDelegations;
    uint256 public totalDelegations = 0;

    event SetGlobalDelegation(address voter, address delegate);
    event SetTokenDelegation(address voter, address tokenContract, address delegate);

    function SVDelegation() public {
        owner = msg.sender;

        // commit the genesis historical delegation to history (like genesis block)
        createDelegation(address(0), 0);
    }

    function createDelegation(address dlgtAddress, uint256 prevDelegationId) internal returns(Delegation) {
        uint256 myDelegationId = totalDelegations;
        historicalDelegations[myDelegationId] = Delegation(myDelegationId, dlgtAddress, block.number, prevDelegationId);
        totalDelegations += 1;

        return historicalDelegations[myDelegationId];
    }

    // get previous delegation, create new delegation via function and then commit to globalDlgts
    function setGlobalDelegation(address dlgtAddress) public {
        uint256 prevDelegationId = globalDlgts[msg.sender].thisDelegationId;
        globalDlgts[msg.sender] = createDelegation(dlgtAddress, prevDelegationId);
        SetGlobalDelegation(msg.sender, dlgtAddress);
    }

    // get previous delegation, create new delegation via function and then commit to tokenDlgts
    function setTokenDelegation(address tokenContract, address dlgtAddress) public {
        uint256 prevDelegationId = tokenDlgts[tokenContract][msg.sender].thisDelegationId;
        tokenDlgts[tokenContract][msg.sender] = createDelegation(dlgtAddress, prevDelegationId);
        SetTokenDelegation(msg.sender, tokenContract, dlgtAddress);
    }

    function resolveDelegation(address voter, address tokenContract) public constant returns(uint256, address, uint256, uint256) {
        Delegation memory _tokenDlgt = tokenDlgts[tokenContract][voter];

        // probs simplest test to check if we have a valid delegation
        if (_tokenDlgt.setAtBlock > 0) {
            return _dlgtRet(_tokenDlgt);
        } else {
            return _dlgtRet(globalDlgts[voter]);
        }
    }

    function _rawGetGlobalDelegation(address _voter) public constant returns(uint256, address, uint256, uint256) {
        return _dlgtRet(globalDlgts[_voter]);
    }

    function _rawGetTokenDelegation(address _voter, address _tokenContract) public constant returns(uint256, address, uint256, uint256) {
        return _dlgtRet(tokenDlgts[_tokenContract][_voter]);
    }

    function _dlgtRet(Delegation d) internal pure returns(uint256, address, uint256, uint256) {
        return (d.thisDelegationId, d.dlgt, d.setAtBlock, d.prevDelegation);
    }
}
