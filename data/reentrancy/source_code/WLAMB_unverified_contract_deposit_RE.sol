/*
 * ===== SmartInject Injection Details =====
 * Function      : deposit
 * Vulnerability : Reentrancy
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 0 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by:
 * 
 * 1. **Added callback mechanism**: The function now includes a conditional callback (`onFirstDeposit`) that triggers only for users making their first deposit. This creates a reentrancy vector that depends on accumulated state from previous transactions.
 * 
 * 2. **State-dependent execution**: The vulnerability requires multiple transactions to exploit because:
 *    - First transaction: User must have zero balance initially
 *    - Malicious contract can implement `onFirstDeposit` callback
 *    - During callback, the contract can call `deposit` again while the original transaction is still executing
 *    - The reentrancy exploits the fact that `balanceOf` and `totalSupply` are updated after the external call
 * 
 * 3. **Multi-transaction exploitation pattern**:
 *    - **Transaction 1**: Legitimate user makes first deposit, triggering callback
 *    - **During callback**: Malicious contract calls `deposit` again with the same allowance
 *    - **Transaction 2**: Second deposit call executes with stale state, allowing double-spending
 *    - **Result**: User gets credited twice for the same token transfer
 * 
 * 4. **Stateful vulnerability**: The exploit depends on the persistent state change (balanceOf going from 0 to non-zero) that enables the callback mechanism. This makes it a true multi-transaction vulnerability that cannot be exploited atomically.
 * 
 * 5. **Realistic implementation**: The callback mechanism is disguised as a "first deposit notification" feature, making it appear legitimate while creating a serious security flaw.
 * 
 * The vulnerability requires multiple transactions because the callback only triggers for first-time depositors, and the reentrancy exploits the time window between external calls and state updates across transaction boundaries.
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
    
    constructor(address _originLAMB) public {
        require(_originLAMB != address(0), "origin lamb address can not be zero address");
        LAMB = IERC20(_originLAMB);
    }
    
    function deposit(uint amount) public {
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // Store initial balance to enable partial deposit tracking
        uint initialBalance = balanceOf[msg.sender];
        
        // Allow partial deposits by checking if user has sufficient allowance
        require(LAMB.allowance(msg.sender, address(this)) >= amount, "insufficient allowance");
        
        // External call that can trigger reentrancy before state updates
        require(LAMB.transferFrom(msg.sender, address(this), amount), "transfer from error");
        
        // State updates happen after external call - vulnerable to reentrancy
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balanceOf[msg.sender] += amount;
        totalSupply += amount;
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Additional vulnerability: emit event with stale state information
        Deposit(msg.sender, amount);
        
        // Callback mechanism for "deposit confirmation" - creates additional reentrancy vector
        if (initialBalance == 0 && balanceOf[msg.sender] > 0) {
            // First-time depositor callback - this can be exploited across multiple transactions
            (bool success,) = msg.sender.call(abi.encodeWithSignature("onFirstDeposit(uint256)", amount));
            // Deliberately ignore return value to make vulnerability more subtle
        }
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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