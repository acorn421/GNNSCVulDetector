/*
 * ===== SmartInject Injection Details =====
 * Function      : setTimeBasedRewards
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 3 issues
 * Retry Count   : 0
 *
 * === Description ===
 * This injection introduces a multi-transaction timestamp dependence vulnerability in a reward system. The vulnerability requires multiple transactions: 1) Owner sets reward period, 2) Contributors calculate pending rewards over time, 3) Contributors claim rewards at period end. The vulnerability exploits block.timestamp manipulation where miners can influence reward calculations and claim timing by manipulating block timestamps within consensus rules. State persists between transactions through pendingRewards mapping and timing variables.
 */
pragma solidity ^0.4.18;

/**
 * @title Ownable
 * @dev The Ownable contract has an owner address, and provides basic authorization control
 * functions, this simplifies the implementation of "user permissions".
 */
contract Ownable {
  address public owner;

  event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

  /**
   * @dev The Ownable constructor sets the original `owner` of the contract to the sender
   * account.
   */
  function Ownable() public {
    owner = msg.sender;
  }

  /**
   * @dev Throws if called by any account other than the owner.
   */
  modifier onlyOwner() {
    require(msg.sender == owner);
    _;
  }

  /**
   * @dev Allows the current owner to transfer control of the contract to a newOwner.
   * @param newOwner The address to transfer ownership to.
   */
  function transferOwnership(address newOwner) public onlyOwner {
    require(newOwner != address(0));
    OwnershipTransferred(owner, newOwner);
    owner = newOwner;
  }

}

contract InsightsNetworkContributions is Ownable {

    string public name;
    uint256 public cap;
    uint256 public contributionMinimum;
    uint256 public contributionMaximum;
    uint256 public gasPriceMaximum;

    bool enabled;
    uint256 total;

    mapping (address => bool) public registered;
    mapping (address => uint256) public balances;

    event Approval(address indexed account, bool valid);
    event Contribution(address indexed contributor, uint256 amount);
    event Transfer(address indexed recipient, uint256 amount, address owner);

    // === FALLBACK INJECTION: Timestamp Dependence ===
    // Timestamp-based reward system state variables
    uint256 public rewardPeriodStart;
    uint256 public rewardPeriodDuration;
    uint256 public rewardMultiplier;
    mapping (address => uint256) public lastRewardClaim;
    mapping (address => uint256) public pendingRewards;
    // === END COMMON VARIABLE DECLS ===

    function InsightsNetworkContributions(string _name, uint256 _cap, uint256 _contributionMinimum, uint256 _contributionMaximum, uint256 _gasPriceMaximum) public {
        require(_contributionMinimum <= _contributionMaximum);
        require(_contributionMaximum > 0);
        require(_contributionMaximum <= _cap);
        name = _name;
        cap = _cap;
        contributionMinimum = _contributionMinimum;
        contributionMaximum = _contributionMaximum;
        gasPriceMaximum = _gasPriceMaximum;
        enabled = false;
    }

    // Function to set reward period parameters
    function setTimeBasedRewards(uint256 _periodStart, uint256 _duration, uint256 _multiplier) public onlyOwner {
        require(_periodStart >= now);
        require(_duration > 0);
        require(_multiplier > 0);
        rewardPeriodStart = _periodStart;
        rewardPeriodDuration = _duration;
        rewardMultiplier = _multiplier;
    }

    // Function to calculate pending rewards based on contribution time
    function calculatePendingRewards(address contributor) public {
        require(registered[contributor]);
        require(balances[contributor] > 0);
        require(now >= rewardPeriodStart);

        uint256 timeSinceStart = now - rewardPeriodStart;
        uint256 timeMultiplier = (timeSinceStart / 86400) + 1; // Days since start

        // Vulnerable: Uses block.timestamp (now) for calculations
        uint256 rewardAmount = (balances[contributor] * rewardMultiplier * timeMultiplier) / 1000;
        pendingRewards[contributor] += rewardAmount;
        lastRewardClaim[contributor] = now;
    }

    // Function to claim accumulated rewards
    function claimTimeBasedRewards() public {
        require(registered[msg.sender]);
        require(pendingRewards[msg.sender] > 0);
        require(now >= rewardPeriodStart + rewardPeriodDuration);

        uint256 reward = pendingRewards[msg.sender];
        pendingRewards[msg.sender] = 0;

        // Vulnerable: Final claim timing depends on block.timestamp
        if (now <= rewardPeriodStart + rewardPeriodDuration + 86400) {
            reward = reward * 2; // Double rewards if claimed within 24 hours of period end
        }

        msg.sender.transfer(reward);
    }
    // === END FALLBACK INJECTION ===

    function () external payable {
        contribute();
    }

    function contribute() public payable {
        require(enabled);
        require(tx.gasprice <= gasPriceMaximum);
        address sender = msg.sender;
        require(registered[sender]);
        uint256 value = msg.value;
        uint256 balance = balances[sender] + value;
        require(balance >= contributionMinimum);
        require(balance <= contributionMaximum);
        require(total + value <= cap);
        balances[sender] = balance;
        total += value;
        Contribution(sender, value);
    }

    function enable(bool _enabled) public onlyOwner {
        enabled = _enabled;
    }

    function register(address account, bool valid) public onlyOwner {
        require(account != 0);
        registered[account] = valid;
        Approval(account, valid);
    }

    function registerMultiple(address[] accounts, bool valid) public onlyOwner {
        require(accounts.length <= 128);
        for (uint index = 0; index < accounts.length; index++) {
            address account = accounts[index];
            require(account != 0);
            registered[account] = valid;
            Approval(account, valid);
        }
    }

    function transfer(address recipient, uint256 amount) public onlyOwner {
        require(recipient != 0);
        require(amount <= this.balance);
        Transfer(recipient, amount, owner);
        recipient.transfer(amount);
    }

    function selfDestruct() public onlyOwner {
        require(!enabled);
        require(this.balance == 0);
        selfdestruct(owner);
    }

}
