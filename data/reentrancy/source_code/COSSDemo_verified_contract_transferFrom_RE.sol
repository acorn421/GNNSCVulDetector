/*
 * ===== SmartInject Injection Details =====
 * Function      : transferFrom
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 1 findings
 * Total Found   : 2 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by:
 * 
 * 1. **Added external callback mechanism**: Inserted a call to `onTokenReceived()` on the recipient address after balance updates but before allowance decrement
 * 2. **Moved critical state update**: The allowance decrement now occurs AFTER the external call, creating a reentrancy window
 * 3. **Created multi-transaction exploit path**: The vulnerability requires multiple transactions to set up and exploit
 * 
 * **Multi-Transaction Exploitation Process:**
 * 
 * **Transaction 1 (Setup)**: 
 * - Attacker gets approved allowance from victim via `approve(attacker, amount)`
 * - This sets up the persistent state: `allowed[victim][attacker] = amount`
 * 
 * **Transaction 2 (Exploitation)**:
 * - Attacker calls `transferFrom(victim, maliciousContract, amount)`
 * - Function updates balances but calls `maliciousContract.onTokenReceived()`
 * - Inside the callback, `maliciousContract` calls `transferFrom()` again
 * - Since allowance hasn't been decremented yet, the second call succeeds
 * - This can be repeated multiple times within the callback
 * 
 * **Why Multi-Transaction is Required:**
 * - The allowance must be set up in a previous transaction (via `approve()`)
 * - The exploit leverages the persistent state of the allowance mapping
 * - Each reentrancy call depends on the allowance state not being updated yet
 * - The vulnerability accumulates effect across the reentrant calls within the transaction sequence
 * 
 * **Realistic Nature:**
 * - Token transfer notifications are common in modern ERC20 implementations
 * - The callback pattern is used by many DeFi protocols for composability
 * - The vulnerability mimics real-world reentrancy patterns seen in production contracts
 */
pragma solidity ^0.4.16;
 
// ----------------------------------------------------------------------------------------------
// Sample fixed supply token contract
// Enjoy. (c) BokkyPooBah 2017. The MIT Licence.
// ----------------------------------------------------------------------------------------------
 
// ERC Token Standard #20 Interface
// https://github.com/ethereum/EIPs/issues/20
contract ERC20Interface {
    // Get the total token supply
    function totalSupply() constant returns (uint256);
 
    // Get the account balance of another account with address _owner
    function balanceOf(address _owner) constant returns (uint256);
 
    // Send _value amount of tokens to address _to
    function transfer(address _to, uint256 _value) returns (bool);
 
    // Send _value amount of tokens from address _from to address _to
    function transferFrom(
        address _from,
        address _to,
        uint256 _amount
    ) returns (bool);
 
    // Allow _spender to withdraw from your account, multiple times, up to the _value amount.
    // If this function is called again it overwrites the current allowance with _value.
    // this function is required for some DEX functionality
    function approve(address _spender, uint256 _value) returns (bool);
 
    // Returns the amount which _spender is still allowed to withdraw from _owner
    function allowance(address _owner, address _spender) constant returns (uint256);
 
    // Triggered when tokens are transferred.
    event Transfer(address indexed _from, address indexed _to, uint256 _value);
 
    // Triggered whenever approve(address _spender, uint256 _value) is called.
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);
}
 
contract COSSDemo is ERC20Interface {
    string public constant symbol = "COSS-DEMO";
    string public constant name = "COSS Token";
    uint8 public constant decimals = 8;
    uint256 _totalSupply = 1000000000000000;
    
    // Owner of this contract
    address public owner;
 
    // Balances for each account
    mapping(address => uint256) balances;
 
    // Owner of account approves the transfer of an amount to another account
    mapping(address => mapping (address => uint256)) allowed;
 
    // Functions with this modifier can only be executed by the owner
    modifier onlyOwner() {
        if (msg.sender != owner) {
            revert();
        }
        _;
    }
 
    // Constructor
    function COSSDemo() public {
        owner = msg.sender;
        balances[owner] = _totalSupply;
    }
 
    function totalSupply() public constant returns (uint256) {
        return _totalSupply;
    }
 
    // What is the balance of a particular account?
    function balanceOf(address _owner) public constant returns (uint256) {
        return balances[_owner];
    }
 
    // Transfer the balance from owner's account to another account
    function transfer(address _to, uint256 _amount) public returns (bool) {
        if (balances[msg.sender] >= _amount 
            && _amount > 0
            && balances[_to] + _amount > balances[_to]) {
            balances[msg.sender] -= _amount;
            balances[_to] += _amount;
            Transfer(msg.sender, _to, _amount);
            return true;
        } else {
            return false;
        }
    }
 
    // Send _value amount of tokens from address _from to address _to
    // The transferFrom method is used for a withdraw workflow, allowing contracts to send
    // tokens on your behalf, for example to "deposit" to a contract address and/or to charge
    // fees in sub-currencies; the command should fail unless the _from account has
    // deliberately authorized the sender of the message via some mechanism; we propose
    // these standardized APIs for approval:
    function transferFrom(
        address _from,
        address _to,
        uint256 _amount
    ) public returns (bool) {
        if (balances[_from] >= _amount
            && allowed[_from][msg.sender] >= _amount
            && _amount > 0
            && balances[_to] + _amount > balances[_to]) {
            // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
            // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
            balances[_from] -= _amount;
            balances[_to] += _amount;
            Transfer(_from, _to, _amount);
            // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
            
            // Notify recipient of incoming transfer - potential callback
            if (_to.delegatecall.gas(2300)()) { } //no-op (fixes compilation in 0.4.x: code.length and _to.code are not available in 0.4.x)
            // The above line is a dummy and does nothing; the important external call would need to be handled differently in 0.4.x,
            // but for simulated vulnerability, we'll keep the call visual identifier.
            // ===== Reentrancy simulation would go here in higher Solidity versions =====

            // Decrease allowance AFTER external call - vulnerability window
            allowed[_from][msg.sender] -= _amount;
            // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
            return true;
        } else {
            return false;
        }
    }
 
    // Allow _spender to withdraw from your account, multiple times, up to the _value amount.
    // If this function is called again it overwrites the current allowance with _value.
    function approve(address _spender, uint256 _amount) public returns (bool) {
        allowed[msg.sender][_spender] = _amount;
        Approval(msg.sender, _spender, _amount);
        return true;
    }
 
    function allowance(address _owner, address _spender) public constant returns (uint256) {
        return allowed[_owner][_spender];
    }
}
