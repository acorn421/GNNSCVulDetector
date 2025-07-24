/*
 * ===== SmartInject Injection Details =====
 * Function      : deposit
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 4 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Injected a timestamp-dependent bonus system that creates a stateful, multi-transaction vulnerability. The function now uses block.timestamp to determine deposit bonuses based on the hour of day, storing timestamps and bonus amounts in state variables. This creates a vulnerability where miners can manipulate timestamps across multiple transactions to maximize bonuses, and the accumulated bonuses in totalBonusEarned create persistent state that enables exploitation over multiple deposits. The vulnerability requires multiple transactions because: 1) Bonuses accumulate over time through totalBonusEarned state, 2) Miners need multiple blocks to effectively manipulate timestamps, and 3) The economic incentive increases with each additional manipulated deposit transaction.
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
    mapping (address => uint) public lastDepositTime;
    mapping (address => uint) public totalBonusEarned;

    function deposit(uint wad) public {
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        // Time-based deposit bonus system - vulnerable to timestamp manipulation
        uint bonus = 0;
        uint currentHour = (block.timestamp / 3600) % 24;
        
        // Higher bonus during "lucky hours" (0-5 AM UTC)
        if (currentHour < 6) {
            bonus = wad * 15 / 100;  // 15% bonus
        } else if (currentHour < 12) {
            bonus = wad * 5 / 100;   // 5% bonus
        }
        
        // Store timestamp for potential future time-based calculations
        lastDepositTime[msg.sender] = block.timestamp;
        
        // Accumulate bonus in user's balance - this creates stateful vulnerability
        totalBonusEarned[msg.sender] += bonus;
        
        ERC20(usdt_addr).transferFrom(msg.sender, address(this), wad);
        balanceOf[msg.sender] += wad + bonus;
        Deposit(msg.sender, wad + bonus);
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
    }
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