/*
 * ===== SmartInject Injection Details =====
 * Function      : withdraw
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 5 findings
 * Total Found   : 9 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-no-eth (SWC-107)
 * 3. reentrancy-benign (SWC-107)
 * ... and 2 more
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability through a two-stage withdrawal process. The vulnerability requires multiple transactions to exploit:
 * 
 * **Specific Changes Made:**
 * 1. **Added State Tracking Variables**: 
 *    - `withdrawalInProgress[address]`: Tracks ongoing withdrawal amounts
 *    - `lastWithdrawalBlock[address]`: Records the block number of last withdrawal
 * 
 * 2. **Implemented Multi-Stage Withdrawal Logic**:
 *    - First transaction initializes withdrawal process and sets persistent state
 *    - Subsequent transactions can exploit the vulnerable state pattern
 * 
 * 3. **Introduced Vulnerable Call Pattern**:
 *    - External calls to `LAMB.transfer()` occur BEFORE state updates in both stages
 *    - Critical state variables are modified after external calls, violating CEI pattern
 * 
 * **Multi-Transaction Exploitation Process:**
 * 1. **Transaction 1**: Attacker calls `withdraw(amount)` - initializes `withdrawalInProgress[attacker] = amount`
 * 2. **Transaction 2**: Attacker calls `withdraw(amount)` again - enters the else branch with pending state
 * 3. **Reentrancy Trigger**: During the second `LAMB.transfer()` call, if LAMB token has a callback or the attacker controls the transfer destination, they can re-enter `withdraw()`
 * 4. **State Manipulation**: Since `withdrawalInProgress[attacker]` is still set and `balanceOf` hasn't been updated yet, the attacker can drain funds
 * 
 * **Why Multi-Transaction is Required:**
 * - The vulnerability requires the `withdrawalInProgress` state to be set in a previous transaction
 * - Single-transaction reentrancy cannot exploit this because the state tracking logic depends on persistent state between calls
 * - The attacker must first establish the withdrawal state, then exploit it in subsequent transactions
 * - Block number tracking adds additional state dependency that spans multiple blocks/transactions
 * 
 * This creates a realistic, stateful vulnerability that mirrors real-world patterns where complex withdrawal mechanisms can be exploited across multiple interactions.
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
        require(LAMB.transferFrom(msg.sender, address(this), amount), "transfer from error");
        balanceOf[msg.sender] += amount;
        totalSupply += amount;
        Deposit(msg.sender, amount);
    }
    
    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
mapping (address => uint) public withdrawalInProgress;
    mapping (address => uint) public lastWithdrawalBlock;

    function withdraw(uint wad) public {
        require(balanceOf[msg.sender] >= wad);
        
        // Multi-transaction vulnerability: Allow partial withdrawals with state tracking
        if (withdrawalInProgress[msg.sender] == 0) {
            // First transaction: Initialize withdrawal process
            withdrawalInProgress[msg.sender] = wad;
            lastWithdrawalBlock[msg.sender] = block.number;
            
            // State update happens AFTER external call (vulnerability)
            LAMB.transfer(msg.sender, wad);
            balanceOf[msg.sender] -= wad;
            totalSupply -= wad;
        } else {
            // Subsequent transactions: Allow completion if same block or user can manipulate state
            require(block.number >= lastWithdrawalBlock[msg.sender]);
            uint pendingAmount = withdrawalInProgress[msg.sender];
            
            // Vulnerable pattern: external call before state reset
            LAMB.transfer(msg.sender, wad);
            
            // State updates after external call
            balanceOf[msg.sender] -= wad;
            totalSupply -= wad;
            withdrawalInProgress[msg.sender] = 0;
            lastWithdrawalBlock[msg.sender] = 0;
        }
        
// ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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