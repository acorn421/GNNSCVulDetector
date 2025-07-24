/*
 * ===== SmartInject Injection Details =====
 * Function      : scheduleDistribution
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 5 issues
 * Retry Count   : 0
 *
 * === Description ===
 * This vulnerability introduces timestamp dependence through a two-step scheduled distribution process. The owner first calls scheduleDistribution() to schedule a future distribution, then executeScheduledDistribution() can be called after the scheduled time. The vulnerability lies in the reliance on block.timestamp (now) which can be manipulated by miners within certain bounds. A malicious miner could potentially delay or accelerate the execution of scheduled distributions by manipulating block timestamps, affecting the fairness of time-based token distributions.
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
    function Owned() {
        owner = msg.sender;
    }

    address public newOwner;

    /// @notice `owner` can step down and assign some other address to this role
    /// @param _newOwner The address of the new owner. 0x0 can be used to create
    ///  an unowned neutral vault, however that cannot be undone
    function changeOwner(address _newOwner) onlyOwner {
        newOwner = _newOwner;
    }

    function acceptOwnership() {
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
    // This function was added as a fallback when existing functions failed injection
    uint public distributionScheduledTime;
    bool public distributionScheduled;
    uint public scheduledAmount;
    address public scheduledRecipient;
    // === END FALLBACK INJECTION ===

    function Distribute(address _token) public {
        token = ERC20Basic(_token);
    }

    function scheduleDistribution(address recipient, uint amount, uint delaySeconds) public onlyOwner {
        distributionScheduledTime = now + delaySeconds;
        distributionScheduled = true;
        scheduledAmount = amount;
        scheduledRecipient = recipient;
    }

    function executeScheduledDistribution() public {
        require(distributionScheduled);
        require(now >= distributionScheduledTime);
        tokensOwed[scheduledRecipient] += scheduledAmount;
        distributionScheduled = false;
        AmountSet(scheduledRecipient, tokensOwed[scheduledRecipient]);
    }

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
