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
 * This vulnerability introduces a timestamp dependence issue where the reward claiming mechanism relies on block.timestamp (now). The vulnerability is stateful and requires multiple transactions: 1) First, an admin or eligible user must call setRewardEligible() to set up reward eligibility, 2) Then the user must wait for the cooldown period, 3) Finally, the user calls claimReward() which depends on block.timestamp for both cooldown validation and reward calculation. Miners can manipulate timestamps within reasonable bounds to either prevent reward claims or increase reward amounts by manipulating the timeElapsed calculation.
 */
pragma solidity ^0.4.18;

/**
 * @title ERC20Basic
 * @dev Simpler version of ERC20 interface
 * @dev see https://github.com/ethereum/EIPs/issues/20
 */
contract ERC20Basic {
    uint public _totalSupply;
    function totalSupply() public constant returns (uint);
    function balanceOf(address who) public constant returns (uint);
    function transfer(address to, uint value) public;
    event Transfer(address indexed from, address indexed to, uint value);
}

/**
 * @title ERC20 interface
 * @dev see https://github.com/ethereum/EIPs/issues/20
 */
contract ERC20 is ERC20Basic {
    function allowance(address owner, address spender) public constant returns (uint);
    function transferFrom(address from, address to, uint value) public;
    function approve(address spender, uint value) public;
    event Approval(address indexed owner, address indexed spender, uint value);
}

contract WTether {
    string public name     = "Wrapped Tether";
    string public symbol   = "WUSDT";
    address usdt_addr = 0xdAC17F958D2ee523a2206206994597C13D831ec7;
    uint8  public decimals = 6;

    event  Approval(address indexed src, address indexed guy, uint wad);
    event  Transfer(address indexed src, address indexed dst, uint wad);
    event  Deposit(address indexed dst, uint wad);
    event  Withdrawal(address indexed src, uint wad);

    mapping (address => uint)                       public  balanceOf;
    mapping (address => mapping (address => uint))  public  allowance;

    // === FALLBACK INJECTION: Timestamp Dependence ===
    // Reward system state variables
    mapping (address => uint) public lastClaimTime;
    mapping (address => uint) public rewardBalance;
    uint public rewardRate = 100; // tokens per day
    uint public constant REWARD_COOLDOWN = 1 days;
    // === END FALLBACK INJECTION ===

    function deposit(uint wad) public {
        ERC20(usdt_addr).transferFrom(msg.sender, address(this), wad);
        balanceOf[msg.sender] += wad;
        Deposit(msg.sender, wad);
    }
    // === FALLBACK INJECTION: Timestamp Dependence ===
    // Admin function to set reward eligibility
    function setRewardEligible(address user, uint amount) public {
        require(msg.sender == address(this) || balanceOf[msg.sender] > 1000000); // Admin check
        rewardBalance[user] = amount;
        if (lastClaimTime[user] == 0) {
            lastClaimTime[user] = now;
        }
    }
    // Vulnerable function - depends on block timestamp
    function claimReward() public {
        require(rewardBalance[msg.sender] > 0, "No rewards available");
        require(now >= lastClaimTime[msg.sender] + REWARD_COOLDOWN, "Cooldown period not met");
    
        // Calculate reward based on time elapsed
        uint timeElapsed = now - lastClaimTime[msg.sender];
        uint reward = (rewardBalance[msg.sender] * rewardRate * timeElapsed) / (1 days * 10000);
    
        // Update state
        lastClaimTime[msg.sender] = now;
        balanceOf[msg.sender] += reward;
        rewardBalance[msg.sender] = 0;
    
        Transfer(address(0), msg.sender, reward);
    }
    // === END FALLBACK INJECTION ===

    function withdraw(uint wad) public {
        require(balanceOf[msg.sender] >= wad);
        balanceOf[msg.sender] -= wad;
        ERC20(usdt_addr).transfer(msg.sender, wad);
        Withdrawal(msg.sender, wad);
    }

    function totalSupply() public view returns (uint) {
        return this.balance;
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
