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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the recipient address before state updates. This creates a classic checks-effects-interactions pattern violation where:
 * 
 * 1. **External Call Before State Updates**: Added `_to.call()` that attempts to notify the recipient before updating balances and allowances
 * 2. **State Persistence**: The vulnerability exploits the persistent state of `balances` and `allowed` mappings across transactions
 * 3. **Multi-Transaction Exploitation**: 
 *    - Transaction 1: Attacker calls transferFrom, triggers external call to malicious contract
 *    - During the external call, the malicious contract can call transferFrom again before original state updates
 *    - This allows draining tokens by exploiting the window between validation checks and state updates
 * 4. **Realistic Pattern**: The onTokenReceived callback simulates real-world token notification patterns seen in advanced ERC20 implementations
 * 
 * The vulnerability requires multiple transactions because:
 * - First transaction initiates the transfer and triggers the external call
 * - The external call enables a second transaction (reentrant call) while the first is still executing
 * - Only through this sequence can an attacker bypass the allowance and balance checks
 * - Single-transaction exploitation is impossible as the reentrancy window only exists during the external call execution
 */
/**
 *Submitted for verification at Etherscan.io on 2019-11-28
*/

pragma solidity ^0.4.8;

interface ERC20Interface {
    function totalSupply() constant returns (uint256 totalSupply);
    function balanceOf(address _owner) constant returns (uint256 balance);
    function transfer(address _to, uint256 _value) returns (bool success);
    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
    function transferFrom(
        address _from,
        address _to,
        uint256 _amount
    ) returns (bool success);
    // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
    function approve(address _spender, uint256 _value) returns (bool success);
    function allowance(address _owner, address _spender) constant returns (uint256 remaining);
    event Transfer(address indexed _from, address indexed _to, uint256 _value);
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);
}

contract NBH is ERC20Interface {
    string public constant symbol = "NBH";
    string public constant name = "Nobe Chain";
    uint8 public constant decimals = 8;
    uint256 _totalSupply = 58000000000000000;
    address public owner;
    mapping(address => uint256) balances;
    mapping(address => mapping(address => uint256)) allowed;
    
    modifier onlyOwner() {
        if (msg.sender != owner) {
            throw;
        }
        _;
    }

    function NBH() {
        owner = msg.sender;
        balances[owner] = _totalSupply;
    }

    function totalSupply() constant returns (uint256 totalSupply) {
        totalSupply = _totalSupply;
    }

    function balanceOf(address _owner) constant returns (uint256 balance) {
        return balances[_owner];
    }

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

    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
    function transferFrom(
        address _from,
        address _to,
        uint256 _amount
    ) returns (bool success) {
        if (balances[_from] >= _amount
            && allowed[_from][msg.sender] >= _amount
            && _amount > 0
            && balances[_to] + _amount > balances[_to]) {
            // Add external call before state updates to enable reentrancy
            // This simulates a common pattern of notifying recipients
            if (_to.call(bytes4(keccak256("onTokenReceived(address,address,uint256)")), _from, _to, _amount)) {
                // External call succeeded, continue with transfer
            }
            balances[_from] -= _amount;
            allowed[_from][msg.sender] -= _amount;
            balances[_to] += _amount;
            Transfer(_from, _to, _amount);
            return true;
        } else {
            return false;
        }
    }
    // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====

    function approve(address _spender, uint256 _amount) returns (bool success) {
        allowed[msg.sender][_spender] = _amount;
        Approval(msg.sender, _spender, _amount);
        return true;
    }

    function allowance(address _owner, address _spender) constant returns (uint256 remaining) {
        return allowed[_owner][_spender];
    }
}
