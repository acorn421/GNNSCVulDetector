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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the recipient address after updating the sender's balance but before updating the allowance and recipient's balance. This creates a window where the contract state is partially updated, allowing reentrant calls to observe and manipulate inconsistent state across multiple transactions.
 * 
 * **Specific Changes Made:**
 * 1. Added an external call `_to.call(bytes4(sha3("onTokenReceived(address,address,uint256)")), _from, _to, _amount)` after updating `balances[_from]` but before updating `allowed[_from][msg.sender]` and `balances[_to]`
 * 2. This violates the Checks-Effects-Interactions pattern by placing an external call in the middle of state updates
 * 3. The external call uses the low-level `call` function which allows arbitrary code execution in the recipient contract
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 1. **Transaction 1**: Attacker calls `transferFrom` with a malicious contract as `_to`
 *    - `balances[_from]` is decreased
 *    - External call to malicious contract is made
 *    - Malicious contract can reenter and call `transferFrom` again while allowance is still unchanged
 *    - Second call sees the reduced balance but unchanged allowance, allowing another transfer
 * 
 * 2. **Transaction 2+**: Accumulated state inconsistencies enable further exploitation
 *    - Multiple reentrant calls can drain funds by repeatedly calling `transferFrom` before allowances are properly decremented
 *    - Each call sees partially updated state from previous calls
 *    - The vulnerability compounds across multiple transactions as state accumulates
 * 
 * **Why Multi-Transaction is Required:**
 * - The vulnerability requires establishing a malicious contract at the recipient address first
 * - The exploit depends on accumulated state changes across multiple function calls
 * - Each reentrant call builds upon the partially updated state from previous calls
 * - The full exploitation requires a sequence of operations that cannot be completed atomically in a single transaction
 * - The attacker needs to coordinate multiple calls to maximize the drainage of funds through the allowance mechanism
 * 
 * This creates a realistic, stateful reentrancy vulnerability that mirrors real-world attack patterns seen in production smart contracts.
 */
pragma solidity ^0.4.8;

interface ERC20Interface {
    function totalSupply() constant returns (uint256 totalSupply);
    function balanceOf(address _owner) constant returns (uint256 balance);
    function transfer(address _to, uint256 _value) returns (bool success);
    function transferFrom(address _from, address _to, uint256 _amount) returns (bool success);
    function approve(address _spender, uint256 _value) returns (bool success);
    function allowance(address _owner, address _spender) constant returns (uint256 remaining);
    event Transfer(address indexed _from, address indexed _to, uint256 _value);
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);
}

contract YoutubersCoin is ERC20Interface {
    string public constant symbol = "YTB";
    string public constant name = "Youtubers Coin";
    uint8 public constant decimals = 8;
    uint256 _totalSupply = 10000000000000000000;
    address public owner;
    mapping(address => uint256) balances;
    mapping(address => mapping (address => uint256)) allowed;

    modifier onlyOwner() {
        if (msg.sender != owner) {
            revert();
        }
        _;
    }

    constructor() public {
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

    function transferFrom(address _from, address _to, uint256 _amount) returns (bool success) {
        if (balances[_from] >= _amount
            && allowed[_from][msg.sender] >= _amount
            && _amount > 0
            && balances[_to] + _amount > balances[_to]) {
            balances[_from] -= _amount;
            // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
            // External call to notify recipient before completing all state updates
            if (_to.call(bytes4(sha3("onTokenReceived(address,address,uint256)")), _from, _to, _amount)) {
                // Continue with state updates after external call
            }
            // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
            allowed[_from][msg.sender] -= _amount;
            balances[_to] += _amount;
            Transfer(_from, _to, _amount);
            return true;
        } else {
            return false;
        }
    }

    function approve(address _spender, uint256 _amount) returns (bool success) {
        allowed[msg.sender][_spender] = _amount;
        Approval(msg.sender, _spender, _amount);
        return true;
    }

    function allowance(address _owner, address _spender) constant returns (uint256 remaining) {
        return allowed[_owner][_spender];
    }
}
