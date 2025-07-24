/*
 * ===== SmartInject Injection Details =====
 * Function      : unVote
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 1 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Introduced a stateful, multi-transaction Timestamp Dependence vulnerability by adding:
 * 
 * 1. **Timestamp-based cooldown mechanism**: Uses `block.timestamp` to enforce a cooldown period between unvote operations, stored in `lastUnvoteTime[msg.sender]`
 * 
 * 2. **Emergency override system**: References `emergencyOverrideTimestamp` state variable that can be manipulated across transactions to create timing-dependent behavior
 * 
 * 3. **State persistence**: The function stores timestamps in state variables that persist between transactions, enabling multi-transaction exploitation
 * 
 * **Multi-Transaction Exploitation Scenarios:**
 * 
 * **Transaction 1**: Initial unVote() call - sets lastUnvoteTime[msg.sender] = block.timestamp
 * **Transaction 2**: Attempt another unVote() - vulnerable to timestamp manipulation by miners who can:
 * - Adjust block.timestamp to bypass cooldown requirements
 * - Exploit the emergency override timing window
 * - Create race conditions between multiple users' timestamp dependencies
 * 
 * **Why Multi-Transaction is Required:**
 * - The vulnerability requires state accumulation (timestamp storage) from previous transactions
 * - Exploitation timing depends on the relationship between stored timestamps and current block.timestamp
 * - Miners can manipulate timestamps across multiple blocks to create exploitation windows
 * - The emergency override logic creates complex timing dependencies that can only be exploited through sequential transactions
 * 
 * **Realistic Attack Vector:**
 * An attacker could coordinate with miners to manipulate block.timestamp values across multiple transactions, bypassing cooldown periods or exploiting emergency override windows to gain unfair voting advantages.
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
    
    // === Added missing declarations for vulnerability injection ===
    mapping(address => uint256) public lastUnvoteTime;
    uint256 public unvoteCooldown = 60; // default cooldown in seconds
    uint256 public emergencyOverrideTimestamp = 0;

    event onVote(address indexed voter, int256 indexed proposalId);
    event onUnVote(address indexed voter, int256 indexed proposalId);

    // Updated to use constructor syntax (for 0.4.18 compatibility, keeping as is)
    function MovementVoting(uint256 _endBlock) public {
        endBlock = _endBlock;
        admin = msg.sender;
    }

    function changeEndBlock(uint256 _endBlock)
    onlyAdmin {
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
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        
        // Add timestamp-based cooldown mechanism
        require(block.timestamp >= lastUnvoteTime[msg.sender] + unvoteCooldown);
        
        int256 proposalId = votes[msg.sender];
        
        // Store current timestamp for cooldown calculation
        lastUnvoteTime[msg.sender] = block.timestamp;
        
        // Check if emergency override is active based on stored timestamp
        if (emergencyOverrideTimestamp > 0 && block.timestamp >= emergencyOverrideTimestamp + 300) {
            // Emergency override active - allow immediate re-voting
            votes[msg.sender] = 0;
        } else {
            votes[msg.sender] = -1;
        }
        
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
        onUnVote(msg.sender, proposalId);
    }

    function votersCount()
    public constant
    returns(uint256) {
        return voters.length;
    }

    function getVoters(uint256 offset, uint256 limit)
    public constant
    returns(address[] _voters, int256[] _proposalIds) {

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
