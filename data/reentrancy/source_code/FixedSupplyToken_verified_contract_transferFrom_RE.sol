/*
 * ===== SmartInject Injection Details =====
 * Function      : transferFrom
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 2 findings
 * Total Found   : 2 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by:
 * 
 * 1. **Added External Call**: Introduced a callback mechanism that calls `onTokenReceived` on the recipient if it's a contract, creating an external call vulnerability point.
 * 
 * 2. **Violated Checks-Effects-Interactions Pattern**: The external call (`_to.call(...)`) happens BEFORE critical state updates (`balances[_from] -= _amount` and `allowed[_from][msg.sender] -= _amount`).
 * 
 * 3. **Created Multi-Transaction Exploitation Window**: The vulnerability requires multiple transactions to exploit:
 *    - **Transaction 1**: Attacker sets up allowances using `approve()` function
 *    - **Transaction 2**: Attacker calls `transferFrom()` which triggers the callback, allowing reentrancy
 *    - **During Reentrancy**: Attacker can call `transferFrom()` again before the original call completes its state updates
 * 
 * 4. **Stateful Nature**: The vulnerability depends on:
 *    - Persistent allowance state set in previous transactions
 *    - Balance state that accumulates across calls
 *    - The timing window between recipient balance update and sender balance/allowance updates
 * 
 * **Multi-Transaction Exploitation Scenario**:
 * - **Setup Phase (Transaction 1)**: Attacker gets approval for large amount via `approve()`
 * - **Exploit Phase (Transaction 2)**: Attacker calls `transferFrom()` to malicious contract
 * - **Reentrancy Phase**: Malicious contract's `onTokenReceived()` callback re-enters `transferFrom()`
 * - **Result**: Attacker can drain funds because allowance hasn't been decremented yet in the original call
 * 
 * **Why Multi-Transaction**: The vulnerability requires prior allowance setup and depends on the specific timing of state updates across transaction boundaries. The allowance mechanism creates a persistent state that enables the reentrancy attack across multiple function calls.
 */
pragma solidity ^0.4.8;
 
// ----------------------------------------------------------------------------------------------
// Comet DeFi token smart contract
// ----------------------------------------------------------------------------------------------
 
// ERC Token Standard #20 Interface
contract ERC20Interface {
    // Get the total token supply
    function totalSupply() constant returns (uint256 totalSupply);
 
    // Get the account balance of another account with address _owner
    function balanceOf(address _owner) constant returns (uint256 balance);
 
    // Send _value amount of tokens to address _to
    function transfer(address _to, uint256 _value) returns (bool success);
 
    // Send _value amount of tokens from address _from to address _to
    // NOTE: Implementation (with vulnerability) needs variables, but interfaces can't declare storage.
    function transferFrom(
        address _from,
        address _to,
        uint256 _amount
    ) returns (bool success);
 
    // Allow _spender to withdraw from your account, multiple times, up to the _value amount.
    // If this function is called again it overwrites the current allowance with _value.
    // this function is required for some DEX functionality
    function approve(address _spender, uint256 _value) returns (bool success);
 
    // Returns the amount which _spender is still allowed to withdraw from _owner
    function allowance(address _owner, address _spender) constant returns (uint256 remaining);
 
    // Triggered when tokens are transferred.
    event Transfer(address indexed _from, address indexed _to, uint256 _value);
 
    // Triggered whenever approve(address _spender, uint256 _value) is called.
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);
}
 
contract FixedSupplyToken is ERC20Interface {
    string public constant symbol = "CMT";
    string public constant name = "Cometa";
    uint8 public constant decimals = 18;
    uint256 _totalSupply = 10000000000000000000000000;
    
    // Owner of this contract
    address public owner;
 
    // Balances for each account
    mapping(address => uint256) balances;
 
    // Owner of account approves the transfer of an amount to another account
    mapping(address => mapping (address => uint256)) allowed;
 
    // Functions with this modifier can only be executed by the owner
    modifier onlyOwner() {
        if (msg.sender != owner) {
            throw;
        }
        _;
    }
 
    // Constructor
    function FixedSupplyToken() {
        owner = msg.sender;
        balances[owner] = _totalSupply;
    }
 
    function totalSupply() constant returns (uint256 totalSup) {
        totalSup = _totalSupply;
    }
 
    // What is the balance of a particular account?
    function balanceOf(address _owner) constant returns (uint256 balance) {
        return balances[_owner];
    }
 
    // Transfer the balance from owner's account to another account
    function transfer(address _to, uint256 _amount) returns (bool success) {
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
    ) returns (bool success) {
        if (balances[_from] >= _amount
            && allowed[_from][msg.sender] >= _amount
            && _amount > 0
            && balances[_to] + _amount > balances[_to]) {
            // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
            // Update recipient balance first
            balances[_to] += _amount;

            // Notify recipient if it's a contract (potential external call)
            // Check for code on _to address (not available in 0.4.8 natively, replaced with extcodesize)
            uint codeLength;
            assembly { codeLength := extcodesize(_to) }
            if (codeLength > 0) {
                // External call before completing state updates - VULNERABILITY
                bool result = _to.call(bytes4(keccak256("onTokenReceived(address,address,uint256)")), _from, _to, _amount);
                if (!result) {
                    // Revert only balance change if call fails, but don't revert transaction
                    balances[_to] -= _amount;
                    return false;
                }
            }
            // State updates happen AFTER external call - CRITICAL VULNERABILITY
            // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
            balances[_from] -= _amount;
            allowed[_from][msg.sender] -= _amount;
            // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
            // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
            Transfer(_from, _to, _amount);
            return true;
        } else {
            return false;
        }
    }

    // Allow _spender to withdraw from your account, multiple times, up to the _value amount.
    // If this function is called again it overwrites the current allowance with _value.
    function approve(address _spender, uint256 _amount) returns (bool success) {
        allowed[msg.sender][_spender] = _amount;
        Approval(msg.sender, _spender, _amount);
        return true;
    }
 
    function allowance(address _owner, address _spender) constant returns (uint256 remaining) {
        return allowed[_owner][_spender];
    }
}
