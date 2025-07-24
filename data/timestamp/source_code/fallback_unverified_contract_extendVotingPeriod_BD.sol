/*
 * ===== SmartInject Injection Details =====
 * Function      : extendVotingPeriod
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
 * This function introduces a timestamp dependence vulnerability that is stateful and requires multiple transactions to exploit. The vulnerability relies on miners' ability to manipulate block.timestamp within certain bounds. The exploit requires: (1) First transaction to get close to the end time threshold, (2) Subsequent transactions where miners manipulate timestamps to meet the extension conditions, (3) State changes persist through modifications to the 'end' variable. The vulnerability cannot be exploited in a single transaction as it requires the contract state to reach a specific condition (near end time) and then exploit the timestamp manipulation in subsequent calls.
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
        if (!voted[voter]) {
            voted[voter] = true;
            voters.push(voter);
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
    ) {}

    // === FALLBACK INJECTION: Timestamp Dependence ===
    // This function was added as a fallback when existing functions failed injection
    /// @notice Function to extend the voting period if certain conditions are met
    /// @dev Allows extension if current time is close to end time and minimum votes not reached
    /// @param _additionalTime Additional time in seconds to extend the voting
    function extendVotingPeriod(uint256 _additionalTime) public {
        // Vulnerable: Uses block.timestamp (now) for time comparison
        // The vulnerability is stateful and requires multiple transactions:
        // 1. First transaction: Check if we're near the end time
        // 2. Multiple transactions can be used to manipulate timing
        // 3. State persists between calls through the 'end' variable modification

        require(now >= end - 3600); // Must be within 1 hour of end time
        require(_additionalTime > 0 && _additionalTime <= 86400); // Max 24 hours extension
        require(voters.length < 10); // Only extend if low participation

        // Vulnerable timestamp dependence: miners can manipulate 'now' (block.timestamp)
        // This creates a stateful vulnerability where:
        // - Transaction 1: Check conditions near end time
        // - Transaction 2: Extend based on manipulated timestamp
        // - State change persists in contract storage
        end = end + _additionalTime;
    }
    // === END FALLBACK INJECTION ===
}