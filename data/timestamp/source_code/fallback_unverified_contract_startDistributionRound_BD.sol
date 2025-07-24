/*
 * ===== SmartInject Injection Details =====
 * Function      : startDistributionRound
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 8 issues
 * Retry Count   : 0
 *
 * === Description ===
 * This vulnerability involves timestamp dependence where miners can manipulate block timestamps to gain unfair advantages. The vulnerability is stateful and multi-transaction: 1) Owner starts distribution round setting timestamp, 2) Users claim with time-based bonuses that depend on manipulable timestamps, 3) The vulnerability persists across multiple transactions and requires accumulated state changes (round start time, user claim status) to be exploitable.
 */
pragma solidity ^0.4.15;

contract Owned {

    /// @dev `owner` is the only address that can call a function with this
    /// modifier
    modifier onlyOwner() {
        require(msg.sender == owner);
        _;
    }

    address public owner;

    /// @notice The Constructor assigns the message sender to be `owner`
    function Owned() public {
        owner = msg.sender;
    }

    address public newOwner;

    /// @notice `owner` can step down and assign some other address to this role
    /// @param _newOwner The address of the new owner. 0x0 can be used to create
    ///  an unowned neutral vault, however that cannot be undone
    function changeOwner(address _newOwner) public onlyOwner {
        newOwner = _newOwner;
    }

    function acceptOwnership() public {
        if (msg.sender == newOwner) {
            owner = newOwner;
        }
    }
}

contract ERC20Basic {
    function transfer(address to, uint256 value) public returns (bool);
    function balanceOf(address who) public constant returns (uint256);
    event Transfer(address indexed from, address indexed to, uint256 value);
}

contract Distribute is Owned {

    mapping (address => uint) public tokensOwed;
    ERC20Basic token;

    event AmountSet(address contributor, uint amount);
    event AmountSent(address contributor, uint amount);

    // === FALLBACK INJECTION: Timestamp Dependence ===
    // The distribution round state variables moved here, outside the constructor
    uint public distributionRoundStart;
    uint public distributionRoundDuration = 24 hours;
    bool public distributionRoundActive = false;
    mapping(address => bool) public hasClaimedInRound;
    // === END VARIABLE DECLARATIONS ===

    function Distribute(address _token) public {
        token = ERC20Basic(_token);
    }

    function startDistributionRound() public onlyOwner {
        distributionRoundStart = now;
        distributionRoundActive = true;
        AmountSet(msg.sender, distributionRoundStart);
    }

    function collectWithTimeBonus() public {
        require(distributionRoundActive);
        require(!hasClaimedInRound[msg.sender]);
        require(tokensOwed[msg.sender] > 0);

        uint amount = tokensOwed[msg.sender];

        // Vulnerable: miners can manipulate timestamp to get bonus
        if (now <= distributionRoundStart + 1 hours) {
            // 20% bonus for early claims
            amount = amount * 120 / 100;
        }

        hasClaimedInRound[msg.sender] = true;
        tokensOwed[msg.sender] = 0;
        token.transfer(msg.sender, amount);
        AmountSent(msg.sender, amount);
    }

    function endDistributionRound() public onlyOwner {
        require(distributionRoundActive);
        require(now >= distributionRoundStart + distributionRoundDuration);

        distributionRoundActive = false;

        // Reset all hasClaimedInRound mappings for next round
        // This would need to be done for all addresses, but simplified here
    }
    // === END FALLBACK INJECTION ===

    function setAmount(address contributor, uint amount) public onlyOwner {
        tokensOwed[contributor] = amount;
    }

    function withdrawAllTokens() public onlyOwner {
        token.transfer(owner, token.balanceOf(address(this)));
    }

    function() public payable {
        collect();
    }

    function collect() public {
        uint amount = tokensOwed[msg.sender];
        require(amount > 0);
        tokensOwed[msg.sender] = 0;
        token.transfer(msg.sender, amount);
        AmountSent(msg.sender, amount);
    }
}
