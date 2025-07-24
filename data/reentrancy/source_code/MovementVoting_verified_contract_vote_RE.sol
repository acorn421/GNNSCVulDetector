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
 * Total Found   : 3 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding a reward system that makes an external call to transfer tokens BEFORE updating the voting state. The vulnerability requires multiple transactions to exploit:
 * 
 * **Specific Changes Made:**
 * 1. Added check for first-time voter status (`firstTimeVoter` boolean)
 * 2. Introduced external call to `IRewardToken(rewardToken).transfer()` before state update
 * 3. The external call occurs BEFORE `votes[msg.sender] = proposalId` is executed
 * 4. Added assumptions of `rewardToken` address and `participationReward` variables existing
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 1. **Transaction 1**: Attacker calls `vote()` with proposalId = 1
 *    - `votes[attacker] == 0` so `firstTimeVoter = true`
 *    - `voters.push(attacker)` executes
 *    - External call to `rewardToken.transfer()` is made
 *    - During this external call, attacker can reenter
 * 
 * 2. **Reentrancy Attack**: During the external call, attacker calls `vote()` again with proposalId = 2
 *    - `votes[attacker]` is still 0 (not yet updated)
 *    - `firstTimeVoter = true` again
 *    - `voters.push(attacker)` executes again (duplicate entry)
 *    - Another reward transfer attempt occurs
 *    - `votes[attacker] = 2` is set
 * 
 * 3. **Transaction 1 Completion**: Original call completes
 *    - `votes[attacker] = 1` overwrites the value
 *    - State is now inconsistent
 * 
 * 4. **Transaction 2**: Attacker can exploit the inconsistent state
 *    - Multiple entries in voters array
 *    - Potential for double rewards
 *    - Vote counting anomalies
 * 
 * **Why Multi-Transaction is Required:**
 * - The vulnerability relies on the persistent state of `votes[msg.sender]` being 0 across the external call
 * - Multiple function calls are needed to exploit the state inconsistency
 * - The attacker needs to trigger the external call and then reenter during that call
 * - The exploitation spans multiple transaction contexts due to the external call mechanism
 * - State accumulation in the `voters` array enables the vulnerability to compound across calls
 */
/**
  * The Movement
  * Decentralized Autonomous Organization
  */
  
pragma solidity ^0.4.18;

interface IRewardToken {
    function transfer(address to, uint256 value) external returns (bool);
}

contract MovementVoting {
    mapping(address => int256) public votes;
    address[] public voters;
    uint256 public endBlock;
	address public admin;
    address public rewardToken;
    uint256 public participationReward;
	
    event onVote(address indexed voter, int256 indexed proposalId);
    event onUnVote(address indexed voter, int256 indexed proposalId);

    constructor(uint256 _endBlock) public {
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
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Check if user is voting for first time to award participation reward
        bool firstTimeVoter = (votes[msg.sender] == 0);
        
        if (firstTimeVoter) {
            voters.push(msg.sender);
            // Award participation reward through external call BEFORE state update
            if (rewardToken != address(0)) {
                IRewardToken(rewardToken).transfer(msg.sender, participationReward);
            }
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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

    function votersCount() public constant returns(uint256) {
        return voters.length;
    }

    function getVoters(uint256 offset, uint256 limit) public constant returns(address[] _voters, int256[] _proposalIds) {

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
