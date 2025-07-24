/*
 * ===== SmartInject Injection Details =====
 * Function      : withdrawRewards
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
 * This vulnerability introduces a multi-transaction timestamp dependence issue. Users must first call accumulateRewards() multiple times over different time periods to build up reward claims, then call withdrawRewards() to claim them. The vulnerability lies in the timestamp-dependent calculations for reward bonuses and timing restrictions. Miners can manipulate block timestamps to either maximize their own rewards during accumulation or time their withdrawals to hit favorable bonus windows. The vulnerability requires multiple transactions: several calls to accumulateRewards() followed by withdrawRewards(), making it stateful and persistent across transactions.
 */
pragma solidity ^0.4.24;

contract Ownable {
    address public owner;

    event OwnershipTransferred(
        address indexed previousOwner,
        address indexed newOwner
    );
    /**
     * @dev The Ownable constructor sets the original `owner` of the contract to the sender
     * account.
     */
    constructor() public {
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
        emit OwnershipTransferred(owner, newOwner);
        owner = newOwner;
    }
}

contract Erc20 {
    function balanceOf(address _owner) public view returns (uint256);
    function transfer(address _to, uint256 _value) public returns (bool);
    function approve(address _spender, uint256 _value) public returns (bool);
}

contract Exchange {
    function ethToTokenSwapInput(uint256 min_tokens, uint256 deadline)
        public
        payable
        returns (uint256);
}

contract LendingPool {
    function deposit( address _reserve, uint256 _amount, uint16 _referralCode) external payable;
}

contract aDaiGateway is Ownable {
    Exchange constant DaiEx = Exchange(0x2a1530C4C41db0B0b2bB646CB5Eb1A67b7158667);
    LendingPool constant lendingPool = LendingPool(0x398eC7346DcD622eDc5ae82352F02bE94C62d119);

    Erc20 constant  dai = Erc20(0x6B175474E89094C44Da98b954EedeAC495271d0F);
    Erc20 constant aDai = Erc20(0xfC1E690f61EFd961294b3e1Ce3313fBD8aa4f85d);

    uint16 constant referral = 47;

    // === FALLBACK INJECTION: Timestamp Dependence ===
    // Mappings and variables need to be declared at contract scope (not inside constructor)
    mapping(address => uint256) public userRewardClaims;
    mapping(address => uint256) public lastClaimTime;
    uint256 public rewardPool;
    uint256 public constant REWARD_PERIOD = 1 hours;
    uint256 public constant MIN_REWARD_INTERVAL = 30 minutes;

    constructor() public {
        dai.approve(0x3dfd23A6c5E8BbcFc9581d2E864a68feb6a076d3, uint256(-1)); //lendingPoolCore
    }

    // Function to accumulate rewards (called by users over time)
    function accumulateRewards() public payable {
        require(msg.value > 0, "Must send ETH to accumulate rewards");
        // Only allow accumulation if enough time has passed
        if (lastClaimTime[msg.sender] != 0) {
            require(now >= lastClaimTime[msg.sender] + MIN_REWARD_INTERVAL, "Too soon to accumulate more rewards");
        }
        // Calculate reward multiplier based on timestamp
        uint256 timeBonus = (now % REWARD_PERIOD) + 1; // Vulnerable: miners can manipulate
        uint256 rewardAmount = (msg.value * timeBonus) / 100;
        userRewardClaims[msg.sender] += rewardAmount;
        rewardPool += msg.value;
        lastClaimTime[msg.sender] = now;
    }
    // Function to withdraw accumulated rewards (requires multiple prior accumulations)
    function withdrawRewards() public {
        require(userRewardClaims[msg.sender] > 0, "No rewards to claim");
        require(lastClaimTime[msg.sender] != 0, "Must accumulate rewards first");
        // Vulnerable: Uses timestamp for reward calculation
        uint256 timeSinceLastClaim = now - lastClaimTime[msg.sender];
        require(timeSinceLastClaim >= REWARD_PERIOD, "Must wait full reward period");
        // Additional time-based bonus (vulnerable to manipulation)
        uint256 timeMultiplier = 1;
        if (now % 3600 < 300) { // First 5 minutes of each hour gives bonus
            timeMultiplier = 2;
        }
        uint256 finalReward = userRewardClaims[msg.sender] * timeMultiplier;
        require(finalReward <= rewardPool, "Insufficient reward pool");
        userRewardClaims[msg.sender] = 0;
        rewardPool -= finalReward;
        msg.sender.transfer(finalReward);
    }
    // === END FALLBACK INJECTION ===

    function() external payable {
        etherToaDai(msg.sender);
    }

    function etherToaDai(address to)
        public
        payable
        returns (uint256 outAmount)
    {
        uint256 amount = DaiEx.ethToTokenSwapInput.value(
            (msg.value * 995) / 1000
        )(1, now);
        lendingPool.deposit(address(dai), amount, referral);
        outAmount = aDai.balanceOf(address(this));
        aDai.transfer(to, outAmount);
    }

    function makeprofit() public {
        owner.transfer(address(this).balance);
    }
}
