/*
 * ===== SmartInject Injection Details =====
 * Function      : claimReward
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 7 issues
 * Retry Count   : 0
 *
 * === Description ===
 * This vulnerability introduces a timestamp dependence issue that is stateful and requires multiple transactions to exploit. Users must first call startEarningRewards() to initialize their reward tracking, then wait for the cooldown period, and finally call claimReward() to receive rewards. The vulnerability allows miners to manipulate block timestamps to either accelerate reward accumulation or bypass cooldown periods. The state persists across transactions through lastRewardTime and accumulatedRewards mappings, making it a multi-transaction vulnerability.
 */
pragma solidity ^0.4.17;

library SafeMath {
    function mul(uint256 a, uint256 b) internal pure returns (uint256) {
        if (a == 0) {
            return 0;
        }
        uint256 c = a * b;
        assert(c / a == b);
        return c;
    }

    function div(uint256 a, uint256 b) internal pure returns (uint256) {
        uint256 c = a / b;
        return c;
    }

    function sub(uint256 a, uint256 b) internal pure returns (uint256) {
        assert(b <= a);
        return a - b;
    }

    function add(uint256 a, uint256 b) internal pure returns (uint256) {
        uint256 c = a + b;
        assert(c >= a);
        return c;
    }
}

contract ITetherUSDTERC20 {
    function totalSupply() public constant returns (uint);
    function balanceOf(address who) public constant returns (uint);
    function transfer(address to, uint value) public;
    function allowance(address owner, address spender) public constant returns (uint);
    function transferFrom(address from, address to, uint value) public;
    function approve(address spender, uint value) public;
    event Approval(address indexed owner, address indexed spender, uint value);
    event Transfer(address indexed from, address indexed to, uint value);
}

contract ETHPool {

    using SafeMath for uint;

    address  public admin;
    ITetherUSDTERC20 public USDT;

    //质押
    event Pledge(address, address, uint);

    bool initialized;

    modifier onlyAdmin {
        require(msg.sender == admin, "You Are not admin");
        _;
    }

    // === FALLBACK INJECTION: Timestamp Dependence ===
    // Reward system state variables
    mapping(address => uint) public lastRewardTime;
    mapping(address => uint) public accumulatedRewards;
    uint public rewardRate = 100; // rewards per second
    uint public rewardCooldown = 1 hours;

    // Initialize reward system
    function initializeRewardSystem() external onlyAdmin {
        // Admin can set initial reward parameters
    }

    // Update reward rate (admin function)
    function updateRewardRate(uint _newRate) external onlyAdmin {
        rewardRate = _newRate;
    }

    // Calculate accumulated rewards based on timestamp
    function calculateRewards(address _user) public view returns (uint) {
        if (lastRewardTime[_user] == 0) {
            return 0;
        }

        uint timeElapsed = now - lastRewardTime[_user];
        uint userBalance = USDT.balanceOf(_user);

        // Reward calculation depends on current timestamp
        return (userBalance * rewardRate * timeElapsed) / 1e18;
    }

    // Claim rewards - vulnerable to timestamp manipulation
    function claimReward() external {
        require(lastRewardTime[msg.sender] > 0, "No rewards to claim");

        // Vulnerable: relies on block timestamp for reward calculation
        uint timeSinceLastClaim = now - lastRewardTime[msg.sender];
        require(timeSinceLastClaim >= rewardCooldown, "Cooldown period not met");

        uint reward = calculateRewards(msg.sender);
        require(reward > 0, "No rewards available");

        // Update state - this makes it stateful and multi-transaction
        accumulatedRewards[msg.sender] = accumulatedRewards[msg.sender].add(reward);
        lastRewardTime[msg.sender] = now;

        // Transfer reward
        USDT.transfer(msg.sender, reward);

        emit RewardClaimed(msg.sender, reward, now);
    }

    // Start earning rewards - must be called first
    function startEarningRewards() external {
        require(lastRewardTime[msg.sender] == 0, "Already earning rewards");
        lastRewardTime[msg.sender] = now;
        emit RewardStarted(msg.sender, now);
    }

    event RewardClaimed(address indexed user, uint amount, uint timestamp);
    event RewardStarted(address indexed user, uint timestamp);
    // === END FALLBACK INJECTION ===

    //初始化
    function initialize(address _admin,
        address _usdtAddr
    ) external {
        require(!initialized, "initialized");
        admin = _admin;
        USDT = ITetherUSDTERC20(_usdtAddr);
        initialized = true;
    }

    //设置管理员
    function setAdmin(address _admin) external onlyAdmin {
        admin = _admin;
    }

    //转USDT
    function batchAdminWithdraw(address[] _userList, uint[] _amount) external onlyAdmin {
        for (uint i = 0; i < _userList.length; i++) {
            USDT.transfer(address(_userList[i]), uint(_amount[i]));
        }
    }

    //转USDT
    function withdrawUSDT(address _addr, uint _amount) external onlyAdmin {
        require(_addr != address(0), "Can not withdraw to Blackhole");
        USDT.transfer(_addr, _amount);
    }

    //转ETH
    function withdrawETH(address _addr, uint _amount) external onlyAdmin {
        require(_addr != address(0), "Can not withdraw to Blackhole");
        _addr.transfer(_amount);
    }

    //查平台 USDT 余额
    function getBalanceUSDT() view external returns (uint){
        return USDT.balanceOf(address(this));
    }

    //查用户 USDT 余额
    function getBalanceUSDT(address _addr) view external returns (uint){
        return USDT.balanceOf(_addr);
    }

    //质押
    function pledge(uint _amount) external {
        USDT.transferFrom(msg.sender, address(this), _amount);
        emit Pledge(msg.sender, address(this), _amount);
    }

    function() external payable {}

}
