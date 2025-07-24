/*
 * ===== SmartInject Injection Details =====
 * Function      : transfer
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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to recipient contracts before state updates. The vulnerability requires multiple transactions to exploit:
 * 
 * **Specific Changes Made:**
 * 1. **Added External Call Before State Updates**: The function now calls `_to.call()` with a callback notification before updating balances
 * 2. **Moved State Updates After External Call**: Critical state changes (balance updates) now occur after the external call, creating a reentrancy window
 * 3. **Added Contract Existence Check**: Uses `_to.code.length > 0` to identify contract recipients that can implement callbacks
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 1. **Setup Transaction**: Attacker deploys a malicious contract that implements `onTokenReceived()` callback
 * 2. **Accumulation Phase**: Attacker performs legitimate transfers to build up balance over multiple transactions
 * 3. **Exploitation Transaction**: When tokens are transferred TO the malicious contract, it reenters `transfer()` during the callback
 * 4. **State Manipulation**: The reentrant call sees the old balance state (before deduction) and can transfer tokens again before the original transfer completes
 * 
 * **Why Multi-Transaction Exploitation is Required:**
 * - **State Accumulation**: The attacker needs to accumulate sufficient balance across multiple transactions to make the exploit profitable
 * - **Contract Deployment**: The malicious callback contract must be deployed in a separate transaction
 * - **Timing Dependencies**: The vulnerability depends on the specific sequence of external calls and state updates across transaction boundaries
 * - **Persistent State Exploitation**: The exploit leverages the fact that balance state persists between transactions, allowing the attacker to manipulate the same state variables across multiple calls
 * 
 * **Exploitation Flow:**
 * 1. Deploy malicious contract with reentrant `onTokenReceived()` callback
 * 2. Accumulate balance through normal transfers over multiple transactions  
 * 3. Trigger the vulnerable transfer TO the malicious contract
 * 4. The callback reenters and drains tokens while original transfer state is still in transition
 * 5. Both the callback transfer and original transfer complete, leading to double-spending
 * 
 * This creates a realistic, stateful vulnerability that requires careful multi-transaction orchestration to exploit, making it valuable for security research and testing.
 */
pragma solidity ^0.4.16;

contract ETH {
    string public constant symbol = "ETH";
    string public constant name = "ETH";
    uint8 public constant decimals = 6;
    uint256 _totalSupply = (10 ** 8) * (10 ** 6);

    address public owner;
 
    mapping(address => uint256) balances; 
    mapping(address => mapping (address => uint256)) allowed;
 
    constructor() public {
        owner = msg.sender;
        balances[owner] = _totalSupply;
    }
 
    function () public {
        revert();
    }

    function totalSupply() constant public returns (uint256) {
        return _totalSupply;
    }
     
    function balanceOf(address _owner) constant public returns (uint256 balance) {
        return balances[_owner];
    }
 
    function transfer(address _to, uint256 _amount) public returns (bool success) {
        if (balances[msg.sender] >= _amount && _amount > 0 && balances[_to] + _amount > balances[_to]) {
            // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
            // Notify recipient before updating state - enables reentrancy
            if (isContract(_to)) {
                // Call external contract which can reenter during state transition
                (bool callSuccess,) = _to.call(abi.encodeWithSignature("onTokenReceived(address,uint256)", msg.sender, _amount));
                // Continue regardless of callback success to maintain functionality
            }
            
            // State update happens after external call - vulnerable to reentrancy
            // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
            balances[msg.sender] -= _amount;
            balances[_to] += _amount;
            Transfer(msg.sender, _to, _amount);
            return true;
        } else {
            return false;
        }
    }

    function transferFrom(address _from, address _to, uint256 _amount) public returns (bool success) {
        if (balances[_from] >= _amount && allowed[_from][msg.sender] >= _amount && _amount > 0 && balances[_to] + _amount > balances[_to]) {
            balances[_from] -= _amount;
            allowed[_from][msg.sender] -= _amount;
            balances[_to] += _amount;
            Transfer(_from, _to, _amount);
            return true;
        } else {
            return false;
        }
    }

    function approve(address _spender, uint256 _amount) public returns (bool success) {
        allowed[msg.sender][_spender] = _amount;
        Approval(msg.sender, _spender, _amount);
        return true;
    }
 
    function allowance(address _owner, address _spender) constant public returns (uint256 remaining) {
        return allowed[_owner][_spender];
    }

    // Helper function to detect if _to is a contract (Solidity <0.5)
    function isContract(address _addr) private view returns (bool) {
        uint256 length;
        assembly { length := extcodesize(_addr) }
        return (length > 0);
    }

    event Transfer(address indexed _from, address indexed _to, uint256 _value);
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);
}
