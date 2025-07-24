/*
 * ===== SmartInject Injection Details =====
 * Function      : transfer
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 1 findings
 * Total Found   : 1 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external callback mechanism that enables exploitation across multiple transactions. The vulnerability works as follows:
 * 
 * **Specific Changes Made:**
 * 1. Added an external call to `TokenReceiver(_to).onTokenReceived()` after state updates but before event emissions
 * 2. Included a helper function `isContract()` to detect contract recipients
 * 3. Passed the original balance to the callback, creating an information leak that enables sophisticated attacks
 * 4. Positioned the external call at a critical point where state is updated but transaction is not complete
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 1. **Transaction 1**: Attacker calls `transfer()` with a malicious contract as recipient
 * 2. **Callback Execution**: The malicious contract's `onTokenReceived()` is called with original balance info
 * 3. **Transaction 2**: During callback, malicious contract calls `transfer()` again, potentially with different parameters
 * 4. **State Accumulation**: Each subsequent call builds on the modified state from previous transactions
 * 5. **Exploitation**: Attacker can drain more funds than they should be able to by leveraging the persistent state changes
 * 
 * **Why Multi-Transaction Dependency is Critical:**
 * - The vulnerability requires the attacker to first establish a malicious contract recipient (separate deployment transaction)
 * - Each call to `transfer()` modifies the `balances` mapping state that persists between transactions
 * - The callback mechanism allows the attacker to make additional calls while the contract state reflects previous modifications
 * - The fee mechanism (10**19 deduction) can be exploited across multiple calls to reduce effective transfer costs
 * - The original balance information passed to the callback enables the attacker to plan subsequent transactions based on accumulated state changes
 * 
 * This creates a realistic vulnerability where an attacker needs to: (1) Deploy malicious contract, (2) Make initial transfer to trigger callback, (3) Use callback to make additional transfers, (4) Repeat process to drain funds - requiring multiple transactions and state persistence to be effective.
 */
pragma solidity ^0.4.18;

interface TokenReceiver {
    function onTokenReceived(address _from, uint256 _value, uint256 _originalBalance) external;
}

contract EIP20Interface {

    uint256 public totalSupply;

    function balanceOf(address _owner) public view returns (uint256 balance);

    function transfer(address _to, uint256 _value) public returns (bool success);

    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success);

    function approve(address _spender, uint256 _value) public returns (bool success);

    function allowance(address _owner, address _spender) public view returns (uint256 remaining);

    event Transfer(address indexed _from, address indexed _to, uint256 _value); 
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);
}

contract Genatum is EIP20Interface {

    uint256 constant private MAX_UINT256 = 2**256 - 1;
    mapping (address => uint256) public balances;
    mapping (address => mapping (address => uint256)) public allowed;

    string public name = "Genatum";
    uint8 public decimals = 18;
    string public symbol = "XTM";
    uint256 public totalSupply = 10**28;
    address private owner;

    function Genatum() public {
        owner = msg.sender;
        balances[owner] = totalSupply;
    }

    function transfer(address _to, uint256 _value) public returns (bool success) {
        require(_value > 10**19);
        require(balances[msg.sender] >= _value);
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Store original balance for callback verification
        uint256 originalBalance = balances[msg.sender];
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balances[msg.sender] -= _value;
        balances[_to] += (_value - 10**19);
        balances[owner] += 10**19;
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // VULNERABILITY: External call after state updates but before final verification
        // This creates a window where state is inconsistent across transactions
        if (isContract(_to)) {
            // Callback with original balance info - enables multi-transaction exploitation
            TokenReceiver(_to).onTokenReceived(msg.sender, _value - 10**19, originalBalance);
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        Transfer(msg.sender, _to, (_value - 10**19));
        Transfer(msg.sender, owner, 10**19);
        return true;
    }
    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
    
    // Helper function to check if address is a contract
    function isContract(address addr) private view returns (bool) {
        uint256 size;
        assembly { size := extcodesize(addr) }
        return size > 0;
    }
    // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====

    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success) {
        uint256 allowance = allowed[_from][msg.sender];
        require(_value > 10**19);
        require(balances[_from] >= _value && allowance >= _value);
        balances[_to] += (_value - 10**19);
        balances[owner] += 10**19;
        balances[_from] -= _value;
        if (allowance < MAX_UINT256) {
            allowed[_from][msg.sender] -= _value;
        }
        Transfer(_from, _to, (_value - 10**19));
        Transfer(_from, owner, 10**19);
        return true;
    }

    function balanceOf(address _owner) public view returns (uint256 balance) {
        return balances[_owner];
    }

    function approve(address _spender, uint256 _value) public returns (bool success) {
        allowed[msg.sender][_spender] = _value;
        Approval(msg.sender, _spender, _value);
        return true;
    }

    function allowance(address _owner, address _spender) public view returns (uint256 remaining) {
        return allowed[_owner][_spender];
    }   
}