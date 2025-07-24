/*
 * ===== SmartInject Injection Details =====
 * Function      : burnFrom
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 3 findings
 * Total Found   : 4 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-benign (SWC-107)
 * 3. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by:
 * 
 * 1. **Added State Variable**: Introduced `pendingBurns` mapping to track burn operations in progress, creating persistent state between transactions.
 * 
 * 2. **External Call Before State Updates**: Added a call to `_from.call()` to notify the token holder about the burn operation, placed BEFORE the critical state updates (balance, allowance, totalSupply modifications).
 * 
 * 3. **Stateful Protection Mechanism**: The `pendingBurns` mapping creates a stateful condition that persists across transactions, making the vulnerability require multiple transaction sequences to exploit.
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 
 * **Transaction 1 (Setup):**
 * - Attacker contracts calls `burnFrom(maliciousContract, amount)`
 * - The malicious contract receives the `onTokenBurn` callback
 * - During the callback, state hasn't been updated yet (balances are still the same)
 * - The malicious contract can call other functions or setup state for future attacks
 * - The `pendingBurns` state is set but then reset, creating a window for exploitation
 * 
 * **Transaction 2 (Exploitation):**
 * - Attacker can exploit the fact that the external call happens before state updates
 * - If the malicious contract implements `onTokenBurn`, it can:
 *   - Call `burnFrom` again during the callback (nested reentrancy)
 *   - Call other functions like `transferFrom` while balances haven't been updated
 *   - Manipulate allowances or trigger other state changes
 *   - The vulnerability requires the attacker to have set up the malicious contract in a previous transaction
 * 
 * **Multi-Transaction Nature:**
 * - The vulnerability requires at least 2 transactions: one to deploy/setup the malicious contract, and another to trigger the burnFrom with reentrancy
 * - The `pendingBurns` state persists between transactions, creating stateful conditions
 * - The external call mechanism requires the attacker to have prepared a contract with the `onTokenBurn` function
 * - The exploit depends on the accumulated state from previous transactions (contract deployment, allowance setup, etc.)
 * 
 * This creates a realistic, stateful reentrancy vulnerability that requires multiple transactions to set up and exploit, making it suitable for security research and testing of multi-transaction vulnerability detection tools.
 */
pragma solidity ^0.4.16;

contract CFNDToken {
    string public name;
    string public symbol;
    uint8 public decimals = 18;
    uint256 public totalSupply;

    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Burn(address indexed from, uint256 value);

    function CFNDToken() public {
        totalSupply = 40000000 * 10 ** uint256(decimals);
        balanceOf[msg.sender] = totalSupply;
        name = "Cryptfunder";
        symbol = "CFND";
    }

    function _transfer(address _from, address _to, uint _value) internal {
        require(_to != 0x0);
        require(balanceOf[_from] >= _value);
        require(balanceOf[_to] + _value > balanceOf[_to]);
        uint previousBalances = balanceOf[_from] + balanceOf[_to];
        balanceOf[_from] -= _value;
        balanceOf[_to] += _value;
        Transfer(_from, _to, _value);
        assert(balanceOf[_from] + balanceOf[_to] == previousBalances);
    }

    function transfer(address _to, uint256 _value) public {
        _transfer(msg.sender, _to, _value);
    }

    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success) {
        require(_value <= allowance[_from][msg.sender]);     
        allowance[_from][msg.sender] -= _value;
        _transfer(_from, _to, _value);
        return true;
    }

    function approve(address _spender, uint256 _value) public returns (bool success) {
        allowance[msg.sender][_spender] = _value;
        return true;
    }

    function burn(uint256 _value) public returns (bool success) {
        require(balanceOf[msg.sender] >= _value);   
        balanceOf[msg.sender] -= _value;            
        totalSupply -= _value;                      
        Burn(msg.sender, _value);
        return true;
    }

    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
mapping (address => bool) public pendingBurns;

    function burnFrom(address _from, uint256 _value) public returns (bool success) {
// ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        require(balanceOf[_from] >= _value);                
        require(_value <= allowance[_from][msg.sender]);    
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Mark burn as pending to prevent immediate re-execution
        pendingBurns[_from] = true;
        
        // External call to notify token holder about burn - REENTRANCY VULNERABILITY
        // This should happen AFTER state updates, but placed here to create vulnerability
        if (_from != msg.sender) {
            // Attempt to call a burn notification function on the token holder's address
            bytes4 selector = bytes4(keccak256("onTokenBurn(address,uint256)"));
            _from.call(selector, msg.sender, _value);
        }
        
        // State updates happen after external call - VULNERABLE TO REENTRANCY
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balanceOf[_from] -= _value;                         
        allowance[_from][msg.sender] -= _value;             
        totalSupply -= _value;                              
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Reset pending state
        pendingBurns[_from] = false;
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        Burn(_from, _value);
        return true;
    }
}