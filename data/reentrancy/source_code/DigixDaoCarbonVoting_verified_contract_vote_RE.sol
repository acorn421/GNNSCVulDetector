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
 * Total Found   : 4 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-eth (SWC-107)
 * 2. reentrancy-benign (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by:
 * 
 * 1. **Added External Call Before State Update**: Inserted `voter.call.value(0)("")` after adding voter to the voters array but before setting `voted[voter] = true`. This creates a reentrancy window where the voter can call back into the contract.
 * 
 * 2. **State Manipulation Window**: The vulnerability exploits the gap between when a voter is added to the voters array and when they are marked as having voted. During reentrancy, the attacker can cast multiple votes before the `voted[voter]` flag is set.
 * 
 * 3. **Multi-Transaction Exploitation**: 
 *    - **Transaction 1**: Attacker calls vote() which triggers the external call, allowing reentrancy
 *    - **Reentrant Calls**: Through the callback, attacker can call vote() again multiple times before `voted[voter] = true` is executed
 *    - **State Accumulation**: Each reentrant call adds the voter to the voters array again and allows them to cast votes, building up fraudulent voting power
 * 
 * 4. **Persistent State Impact**: The vulnerability creates permanent state corruption where:
 *    - The voter appears multiple times in the voters array
 *    - Multiple votes are recorded for the same voter
 *    - The vote tallying becomes skewed due to duplicate voter entries
 * 
 * 5. **Why Multi-Transaction is Required**: 
 *    - The attack requires the initial vote transaction to trigger the external call
 *    - Subsequent reentrant calls (technically sub-transactions) exploit the state inconsistency
 *    - The full impact only manifests when vote tallies are calculated across the accumulated fraudulent state
 *    - Single transaction exploitation is impossible because the reentrancy window only exists during the external call sequence
 * 
 * This creates a realistic vulnerability where an attacker can manipulate voting results by exploiting the reentrancy window to cast multiple votes and appear as multiple voters in the system.
 */
pragma solidity ^0.4.24;

/// @title DigixDAO Carbon Voting contract
/// @author Digix Holdings
/// @notice NumberCarbonVoting contract, generalized carbon voting contract
contract NumberCarbonVoting {
    uint256 public start;
    uint256 public end;
    struct VoteItem {
        bytes32 title;
        uint256 minValue;
        uint256 maxValue;
        mapping (address => uint256) votes;
    }

    mapping(uint256 => VoteItem) public voteItems;
    uint256 public itemCount;

    mapping(address => bool) public voted;
    address[] public voters;

    /// @notice Constructor, accept the number of voting items, and their infos
    /// @param _itemCount Number of voting items
    /// @param _titles List of titles of the voting items
    /// @param _minValues List of min values for the voting items
    /// @param _maxValues List of max values for the voting items
    /// @param _start Start time of the voting (UTC)
    /// @param _end End time of the voting (UTC)
    constructor (
        uint256 _itemCount,
        bytes32[] _titles,
        uint256[] _minValues,
        uint256[] _maxValues,
        uint256 _start,
        uint256 _end
    )
        public
    {
        itemCount = _itemCount;
        for (uint256 i=0;i<itemCount;i++) {
            voteItems[i].title = _titles[i];
            voteItems[i].minValue = _minValues[i];
            voteItems[i].maxValue = _maxValues[i];
        }
        start = _start;
        end = _end;
    }

    /// @notice Function to case vote in this carbon voting
    /// @dev Every item must be voted on. Reverts if number of votes is
    ///      not equal to the itemCount
    /// @param _votes List of votes on the voting items
    function vote(uint256[] _votes) public {
        require(_votes.length == itemCount);
        require(now >= start && now < end);

        address voter = msg.sender;
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Check if voter has already voted
        if (!voted[voter]) {
            // Add voter to the list first (but don't mark as voted yet)
            voters.push(voter);
            
            // Notify external voting registry before marking as voted
            // This external call creates a reentrancy window
            if (address(this).balance > 0) {
                voter.call.value(0)("");
            }
            
            // Mark as voted AFTER external call - vulnerable to reentrancy
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
            voted[voter] = true;
        }

        for (uint256 i=0;i<itemCount;i++) {
            require(_votes[i] >= voteItems[i].minValue && _votes[i] <= voteItems[i].maxValue);
            voteItems[i].votes[voter] = _votes[i];
        }
    }

    function getAllVoters() public view
        returns (address[] _voters)
    {
        _voters = voters;
    }

    function getVotesForItem(uint256 _itemIndex) public view
        returns (address[] _voters, uint256[] _votes)
    {
        uint256 _voterCount = voters.length;
        require(_itemIndex < itemCount);
        _voters = voters;
        _votes = new uint256[](_voterCount);
        for (uint256 i=0;i<_voterCount;i++) {
            _votes[i] = voteItems[_itemIndex].votes[_voters[i]];
        }
    }

    function getVoteItemDetails(uint256 _itemIndex) public view
        returns (bytes32 _title, uint256 _minValue, uint256 _maxValue)
    {
        _title = voteItems[_itemIndex].title;
        _minValue = voteItems[_itemIndex].minValue;
        _maxValue = voteItems[_itemIndex].maxValue;
    }

    function getUserVote(address _voter) public view
        returns (uint256[] _votes, bool _voted)
    {
        _voted = voted[_voter];
        _votes = new uint256[](itemCount);
        for (uint256 i=0;i<itemCount;i++) {
            _votes[i] = voteItems[i].votes[_voter];
        }
    }
}

/// @notice The DigixDAO Carbon Voting contract, this in turn calls the
///         NumberCarbonVoting contract
/// @dev  This contract will be used for carbon voting on
///       minimum DGDs for Moderator status and
///       Rewards pool for Moderators
contract DigixDaoCarbonVoting is NumberCarbonVoting {
    constructor (
        uint256 _itemCount,
        bytes32[] _titles,
        uint256[] _minValues,
        uint256[] _maxValues,
        uint256 _start,
        uint256 _end
    ) public NumberCarbonVoting(
        _itemCount,
        _titles,
        _minValues,
        _maxValues,
        _start,
        _end
    ) {
    }
}