/*
 * ===== SmartInject Injection Details =====
 * Function      : withdraw
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 3 findings
 * Total Found   : 6 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-benign (SWC-107)
 * 3. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced stateful multi-transaction reentrancy vulnerability by:
 * 1. Adding pendingWithdrawals mapping that accumulates across transactions
 * 2. Moving balanceOf state update to AFTER external call, creating classic reentrancy window
 * 3. Adding withdrawal threshold mechanism that tracks cumulative withdrawals
 * 4. Creating reset logic that can be manipulated through multiple reentrancy attacks
 * 5. The vulnerability requires multiple transactions: initial setup calls to build pending state, then reentrancy attack to exploit the post-call state updates
 * 
 * The attack scenario:
 * - Transaction 1: Normal withdraw to build up pendingWithdrawals state
 * - Transaction 2: Withdraw with reentrancy attack during transfer call
 * - During reentrancy: Call withdraw again before balanceOf is updated
 * - This allows draining more funds than balance should allow
 * - The pendingWithdrawals reset logic can be exploited to bypass tracking across multiple attack transactions
 * 
 * This creates a realistic multi-transaction vulnerability where the attacker must first establish state through normal usage, then exploit the reentrancy window in subsequent transactions.
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
    function transfer(address to, uint value) public returns (bool);
    event Transfer(address indexed from, address indexed to, uint value);
}

/**
 * @title ERC20 interface
 * @dev see https://github.com/ethereum/EIPs/issues/20
 */
contract ERC20 is ERC20Basic {
    function allowance(address owner, address spender) public constant returns (uint);
    function transferFrom(address from, address to, uint value) public returns (bool);
    function approve(address spender, uint value) public returns (bool);
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

    // Declarations to fix compile errors
    mapping(address => uint) public pendingWithdrawals;
    mapping(address => uint) public lastWithdrawalReset;
    uint public withdrawalThreshold = 1000000; // example threshold

    function deposit(uint wad) public {
        ERC20(usdt_addr).transferFrom(msg.sender, address(this), wad);
        balanceOf[msg.sender] += wad;
        emit Deposit(msg.sender, wad);
    }
    function withdraw(uint wad) public {
        require(balanceOf[msg.sender] >= wad);
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Track pending withdrawals that accumulate across transactions
        pendingWithdrawals[msg.sender] += wad;
        
        // External call before state finalization - reentrancy vector
        require(ERC20(usdt_addr).transfer(msg.sender, wad), "Transfer failed");
        
        // State update occurs after external call - vulnerable to manipulation
        balanceOf[msg.sender] -= wad;
        
        // Process accumulated pending withdrawals if threshold reached
        if (pendingWithdrawals[msg.sender] >= withdrawalThreshold) {
            // Reset pending amount - can be exploited across multiple transactions
            pendingWithdrawals[msg.sender] = 0;
            lastWithdrawalReset[msg.sender] = block.timestamp;
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        emit Withdrawal(msg.sender, wad);
    }

    function totalSupply() public view returns (uint) {
        return this.balance;
    }

    function approve(address guy, uint wad) public returns (bool) {
        allowance[msg.sender][guy] = wad;
        emit Approval(msg.sender, guy, wad);
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

        emit Transfer(src, dst, wad);

        return true;
    }
}
