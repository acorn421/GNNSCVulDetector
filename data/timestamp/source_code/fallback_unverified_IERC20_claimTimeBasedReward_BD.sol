/*
 * ===== SmartInject Injection Details =====
 * Function      : claimTimeBasedReward
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
 * This vulnerability exploits timestamp dependence in a multi-transaction reward claiming system. The vulnerability requires: 1) First transaction to initialize the reward period with future timestamps, 2) Multiple subsequent transactions to claim rewards based on manipulated timestamps. Miners can manipulate block timestamps within reasonable bounds (typically 15 seconds) to maximize reward calculations, allowing them to accumulate more rewards than intended over multiple claiming transactions. The vulnerability is stateful because it depends on lastClaimTime and accumulatedRewards that persist between transactions.
 */
pragma solidity ^0.4.18;

interface IERC20 {
    event Approval(address indexed owner, address indexed spender, uint value);
    event Transfer(address indexed from, address indexed to, uint value);

    function name() external view returns (string memory);
    function symbol() external view returns (string memory);
    function decimals() external view returns (uint8);
    function totalSupply() external view returns (uint);
    function balanceOf(address owner) external view returns (uint);
    function allowance(address owner, address spender) external view returns (uint);

    function approve(address spender, uint value) external returns (bool);
    function transfer(address to, uint value) external returns (bool);
    function transferFrom(address from, address to, uint value) external returns (bool);
}

contract WLAMB {
    string public name     = "Childhood of Zuckerberg Goat, Wrapped LAMB";
    string public symbol   = "WLAMB";
    uint8  public decimals = 18;

    event  Approval(address indexed src, address indexed guy, uint wad);
    event  Transfer(address indexed src, address indexed dst, uint wad);
    event  Deposit(address indexed dst, uint wad);
    event  Withdrawal(address indexed src, uint wad);

    mapping (address => uint)                       public  balanceOf;
    mapping (address => mapping (address => uint))  public  allowance;
    
    IERC20 LAMB;
    
    uint public totalSupply;
    
    // === FALLBACK INJECTION: Timestamp Dependence ===
    // This function was added as a fallback when existing functions failed injection
    // Timestamp-dependent reward claiming system
    uint public rewardStartTime;
    uint public rewardEndTime;
    uint public rewardRate = 100; // rewards per second
    mapping(address => uint) public lastClaimTime;
    mapping(address => uint) public accumulatedRewards;
    
    event RewardClaimed(address indexed user, uint reward);
    
    function initializeRewardPeriod(uint _startTime, uint _endTime) public {
        require(_startTime > now, "Start time must be in the future");
        require(_endTime > _startTime, "End time must be after start time");
        rewardStartTime = _startTime;
        rewardEndTime = _endTime;
    }
    
    function claimTimeBasedReward() public {
        require(balanceOf[msg.sender] > 0, "Must have WLAMB balance to claim rewards");
        require(now >= rewardStartTime, "Reward period not started");
        require(now <= rewardEndTime, "Reward period ended");
        
        uint claimTime = now;
        if (lastClaimTime[msg.sender] == 0) {
            lastClaimTime[msg.sender] = rewardStartTime;
        }
        
        uint timeDiff = claimTime - lastClaimTime[msg.sender];
        uint reward = (balanceOf[msg.sender] * rewardRate * timeDiff) / 1000000;
        
        accumulatedRewards[msg.sender] += reward;
        balanceOf[msg.sender] += reward;
        totalSupply += reward;
        lastClaimTime[msg.sender] = claimTime;
        
        RewardClaimed(msg.sender, reward);
    }
    // === END FALLBACK INJECTION ===

    constructor(address _originLAMB) public {
        require(_originLAMB != address(0), "origin lamb address can not be zero address");
        LAMB = IERC20(_originLAMB);
    }
    
    function deposit(uint amount) public {
        require(LAMB.transferFrom(msg.sender, address(this), amount), "transfer from error");
        balanceOf[msg.sender] += amount;
        totalSupply += amount;
        Deposit(msg.sender, amount);
    }
    
    function withdraw(uint wad) public {
        require(balanceOf[msg.sender] >= wad);
        balanceOf[msg.sender] -= wad;
        totalSupply -= wad;
        LAMB.transfer(msg.sender, wad);
        Withdrawal(msg.sender, wad);
    }

    function approve(address guy, uint wad) public returns (bool) {
        allowance[msg.sender][guy] = wad;
        Approval(msg.sender, guy, wad);
        return true;
    }

    function transfer(address dst, uint wad) public returns (bool) {
        return transferFrom(msg.sender, dst, wad);
    }

    function transferFrom(address src, address dst, uint wad)
        public
        returns (bool)
    {
        require(balanceOf[src] >= wad);

        if (src != msg.sender && allowance[src][msg.sender] != uint(-1)) {
            require(allowance[src][msg.sender] >= wad);
            allowance[src][msg.sender] -= wad;
        }

        balanceOf[src] -= wad;
        balanceOf[dst] += wad;

        Transfer(src, dst, wad);

        return true;
    }
}
