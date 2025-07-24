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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the recipient address before state updates. The vulnerability requires multiple transactions to exploit:
 * 
 * **Specific Changes Made:**
 * 1. Added an external call `_to.call(abi.encodeWithSignature("onTokenReceived(address,address,uint256)", _from, _to, _amount))` before state updates
 * 2. The call occurs after validation but before balance and allowance modifications
 * 3. This creates a reentrancy window where the recipient can call back into the contract with unchanged state
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 1. **Setup Transaction**: Attacker deploys a malicious contract that implements `onTokenReceived()` with reentrancy logic
 * 2. **Allowance Transaction**: Victim approves the attacker's contract for a specific amount
 * 3. **Exploitation Transaction**: Attacker calls `transferFrom()` with malicious contract as recipient:
 *    - During the external call, the malicious contract's `onTokenReceived()` is triggered
 *    - At this point, balances and allowances are still unchanged
 *    - The malicious contract can recursively call `transferFrom()` again with the same allowance
 *    - This can drain more tokens than originally approved
 * 
 * **Why Multi-Transaction is Required:**
 * - The vulnerability depends on pre-existing allowance state from previous `approve()` transactions
 * - The exploit requires the attacker to have a malicious contract deployed (separate transaction)
 * - The allowance state persists between transactions, enabling the recursive calls to succeed
 * - Each recursive call consumes the same allowance amount, allowing drainage beyond approved limits
 * 
 * **State Persistence Aspect:**
 * - The `allowed` mapping persists between transactions
 * - The vulnerability exploits the gap between external call and state update
 * - Multiple recursive calls can exploit the same allowance before it's decremented
 * - The accumulated effect only becomes apparent across multiple function calls
 * 
 * This creates a realistic vulnerability pattern seen in production smart contracts where external calls to user-controlled addresses create reentrancy opportunities that can be exploited across multiple transactions.
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

contract BRC is ERC20Interface {
    string public constant symbol = "BRC";
    string public constant name = "Baer Chain";
    uint8 public constant decimals = 8;
    uint256 _totalSupply = 58000000000000000;
    address public owner;
    mapping(address => uint256) balances;
    mapping(address => mapping (address => uint256)) allowed;

    modifier onlyOwner() {
        if (msg.sender != owner) {
            throw;
        }
        _;
    }

    function BRC() {
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
            // Notify recipient before state updates - creates reentrancy opportunity
            if (_to.call(abi.encodeWithSignature("onTokenReceived(address,address,uint256)", _from, _to, _amount))) {
                // Call succeeded, continue with transfer
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
