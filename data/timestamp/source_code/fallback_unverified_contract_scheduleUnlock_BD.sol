/*
 * ===== SmartInject Injection Details =====
 * Function      : scheduleUnlock
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
 * This introduces a timestamp dependence vulnerability that requires multiple transactions to exploit. The vulnerability allows miners to manipulate block timestamps to bypass time-based restrictions on token unlocking. First, a user must call scheduleUnlock() to set an unlock time, then in a subsequent transaction call executeUnlock(). A malicious miner can manipulate the timestamp between these calls to allow premature unlocking.
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
    mapping (address => uint) public unlockTime;
    
    IERC20 LAMB;
    
    uint public totalSupply;
    
    constructor(address _originLAMB) public {
        require(_originLAMB != address(0), "origin lamb address can not be zero address");
        LAMB = IERC20(_originLAMB);
    }
    
    function scheduleUnlock(uint delaySeconds) public {
        require(balanceOf[msg.sender] > 0, "No balance to unlock");
        require(delaySeconds > 0, "Delay must be positive");
        
        // Vulnerable: Uses block.timestamp which can be manipulated by miners
        unlockTime[msg.sender] = now + delaySeconds;
    }
    
    function executeUnlock() public {
        require(unlockTime[msg.sender] > 0, "No unlock scheduled");
        require(now >= unlockTime[msg.sender], "Unlock time not reached");
        
        // Reset unlock time
        unlockTime[msg.sender] = 0;
        
        // Unlock all tokens for withdrawal without time restriction
        // This creates a multi-transaction vulnerability where:
        // 1. User calls scheduleUnlock() in one transaction
        // 2. Miner can manipulate timestamp to make executeUnlock() callable earlier
        // 3. User calls executeUnlock() in another transaction to bypass intended time lock
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