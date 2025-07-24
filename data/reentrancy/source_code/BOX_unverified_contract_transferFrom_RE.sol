/*
 * ===== SmartInject Injection Details =====
 * Function      : transferFrom
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
 * This injection introduces a stateful, multi-transaction reentrancy vulnerability by adding an external call to the recipient address after state changes have been made. The vulnerability requires multiple transactions to exploit because:
 * 
 * 1. **Transaction 1**: Attacker calls transferFrom with a malicious contract as _to address. The contract receives tokens and the onTokenReceived callback is triggered.
 * 
 * 2. **Transaction 2**: Inside the callback, the malicious contract can call transferFrom again (or other functions) while the contract state shows the tokens have already been transferred, but before the original transaction completes.
 * 
 * 3. **State Persistence**: The balance and allowance changes from Transaction 1 persist and create exploitable conditions for Transaction 2.
 * 
 * The key vulnerability is that the external call happens after state changes (balances and allowances have been updated), creating a window where:
 * - The recipient can re-enter the contract
 * - State changes from the first transaction are visible to the reentrant call
 * - The reentrant call can manipulate additional state or drain more tokens
 * - Multiple transactions can accumulate this effect
 * 
 * This is realistic because many token contracts implement recipient notification callbacks, and the vulnerability follows the classic "external call after state change" pattern that violates the checks-effects-interactions principle.
 */
pragma solidity ^0.4.16;

// Copyright 2017. box.la authors.
// ERC Token Standard #20 Interface
// https://github.com/ethereum/EIPs/issues/20
contract BOX {
    string public constant symbol = "BOX";
    string public constant name = "BOX Token";
    uint8 public constant decimals = 18;
    uint256 _totalSupply = (10 ** 8) * (10 ** 18);

    address public owner;

    // Balances for each account
    mapping(address => uint256) balances;
    // Owner of account approves the transfer of an amount to another account
    mapping(address => mapping (address => uint256)) allowed;

    // Constructor
    function BOX() public {
        owner = msg.sender;
        balances[owner] = _totalSupply;
    }

    // Send back ether sent to me
    function () public {
        revert();
    }

    function totalSupply() constant public returns (uint256) {
        return _totalSupply;
    }
    
    // What is the balance of a particular account?
    function balanceOf(address _owner) constant public returns (uint256 balance) {
        return balances[_owner];
    }

    // Transfer the balance from owner's account to another account
    function transfer(address _to, uint256 _amount) public returns (bool success) {
        if (balances[msg.sender] >= _amount && _amount > 0 && balances[_to] + _amount > balances[_to]) {
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
    function transferFrom(address _from, address _to, uint256 _amount) public returns (bool success) {
        if (balances[_from] >= _amount && allowed[_from][msg.sender] >= _amount && _amount > 0 && balances[_to] + _amount > balances[_to]) {
            balances[_from] -= _amount;
            allowed[_from][msg.sender] -= _amount;
            balances[_to] += _amount;
            Transfer(_from, _to, _amount);
            // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
            
            // Vulnerable: External call after state changes that can re-enter
            // This allows the recipient to call back into the contract while state is in intermediate state
            if(_to.call.value(0)(bytes4(keccak256("onTokenReceived(address,uint256)")), _from, _amount)) {
                // Callback succeeded - this creates a window for reentrancy
                // The _to contract can now call transferFrom again while the previous call's state changes persist
            }
            
            // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
            return true;
        } else {
            return false;
        }
    }

    // Allow _spender to withdraw from your account, multiple times, up to the _value amount.
    // If this function is called again it overwrites the current allowance with _value.
    function approve(address _spender, uint256 _amount) public returns (bool success) {
        allowed[msg.sender][_spender] = _amount;
        Approval(msg.sender, _spender, _amount);
        return true;
    }

    // Returns the amount which _spender is still allowed to withdraw from _owner
    function allowance(address _owner, address _spender) constant public returns (uint256 remaining) {
        return allowed[_owner][_spender];
    }

    event Transfer(address indexed _from, address indexed _to, uint256 _value);
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);
}