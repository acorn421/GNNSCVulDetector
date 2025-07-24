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
 * Total Found   : 3 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to notify the recipient contract about token receipt. The vulnerability is created by placing this external call after balance updates but before allowance reduction, violating the Checks-Effects-Interactions pattern. This creates a window where an attacker can re-enter the function during the external call and exploit the inconsistent state where balances are updated but allowances haven't been reduced yet.
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 
 * **Transaction 1 (Setup):**
 * - Attacker deploys a malicious contract that implements `onTokenReceived`
 * - Attacker gets approval from a victim account to spend tokens
 * - The malicious contract is now ready to exploit
 * 
 * **Transaction 2 (Exploitation):**
 * - Attacker calls `transferFrom` to transfer tokens from victim to malicious contract
 * - Function updates balances: `balanceOf[victim] -= value` and `balanceOf[attacker] += value`
 * - External call is made to `attacker.onTokenReceived()` 
 * - **REENTRANCY WINDOW**: Inside `onTokenReceived`, the malicious contract calls `transferFrom` again
 * - On re-entry, the allowance check still passes because `allowance[victim][attacker] -= value` hasn't executed yet
 * - Attacker can drain more tokens than originally approved
 * 
 * **Why Multi-Transaction is Required:**
 * 1. **State Accumulation**: The attacker needs to first establish approval in Transaction 1
 * 2. **Stateful Exploitation**: The vulnerability depends on the persistent allowance state from the first transaction
 * 3. **Callback Dependency**: The reentrancy is only possible through the callback mechanism triggered in Transaction 2
 * 4. **Non-Atomic Nature**: The exploit spans multiple function calls across different transactions, making it impossible to execute in a single atomic transaction
 * 
 * The vulnerability is realistic because recipient notifications are common in modern tokens, and the placement of the external call creates a genuine security flaw that mirrors real-world reentrancy patterns.
 */
/****/
pragma solidity ^0.4.8;
contract tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData); }

contract JinKuangLian{
    string public standard = 'JinKuangLian 0.1';
    string public name;
    string public symbol;
    uint8 public decimals;
    uint256 public totalSupply;

    /* This creates an array with all balances */
    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;

    /* This generates a public event on the blockchain that will notify clients */
    event Transfer(address indexed from, address indexed to, uint256 value);

    /* This notifies clients about the amount burnt */
    event Burn(address indexed from, uint256 value);

    /* Initializes contract with initial supply tokens to the creator of the contract */
    function JinKuangLian() {
        balanceOf[msg.sender] =  1200000000 * 1000000000000000000;              // Give the creator all initial tokens
        totalSupply =  1200000000 * 1000000000000000000;                        // Update total supply
        name = "JinKuangLian";                                   // Set the name for display purposes
        symbol = "JKL";                               // Set the symbol for display purposes
        decimals = 18;                            // Amount of decimals for display purposes
    }

    /* Send coins */
    function transfer(address _to, uint256 _value) {
        if (_to == 0x0) throw;                               // Prevent transfer to 0x0 address. Use burn() instead
        if (balanceOf[msg.sender] < _value) throw;           // Check if the sender has enough
        if (balanceOf[_to] + _value < balanceOf[_to]) throw; // Check for overflows
        balanceOf[msg.sender] -= _value;                     // Subtract from the sender
        balanceOf[_to] += _value;                            // Add the same to the recipient
        Transfer(msg.sender, _to, _value);                   // Notify anyone listening that this transfer took place
    }

    /* Allow another contract to spend some tokens in your behalf */
    function approve(address _spender, uint256 _value)
        returns (bool success) {
        allowance[msg.sender][_spender] = _value;
        return true;
    }

    /* Approve and then communicate the approved contract in a single tx */
    function approveAndCall(address _spender, uint256 _value, bytes _extraData)
        returns (bool success) {
        tokenRecipient spender = tokenRecipient(_spender);
        if (approve(_spender, _value)) {
            spender.receiveApproval(msg.sender, _value, this, _extraData);
            return true;
        }
    }

    /* A contract attempts to get the coins */
    function transferFrom(address _from, address _to, uint256 _value) returns (bool success) {
        if (_to == 0x0) throw;                                // Prevent transfer to 0x0 address. Use burn() instead
        if (balanceOf[_from] < _value) throw;                 // Check if the sender has enough
        if (balanceOf[_to] + _value < balanceOf[_to]) throw;  // Check for overflows
        if (_value > allowance[_from][msg.sender]) throw;     // Check allowance
        balanceOf[_from] -= _value;                           // Subtract from the sender
        balanceOf[_to] += _value;                             // Add the same to the recipient
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Notify recipient if it's a contract - VULNERABILITY: External call before state finalization
        if (_to != tx.origin) {
            // Check if _to is a contract by attempting to call a notification method
            bool callSuccess = _to.call(bytes4(keccak256("onTokenReceived(address,address,uint256)")), _from, _to, _value);
            // Continue regardless of call success to maintain compatibility
        }
        
        allowance[_from][msg.sender] -= _value;               // CRITICAL: Allowance update after external call
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        Transfer(_from, _to, _value);
        return true;
    }

    function burn(uint256 _value) returns (bool success) {
        if (balanceOf[msg.sender] < _value) throw;            // Check if the sender has enough
        balanceOf[msg.sender] -= _value;                      // Subtract from the sender
        totalSupply -= _value;                                // Updates totalSupply
        Burn(msg.sender, _value);
        return true;
    }

    function burnFrom(address _from, uint256 _value) returns (bool success) {
        if (balanceOf[_from] < _value) throw;                // Check if the sender has enough
        if (_value > allowance[_from][msg.sender]) throw;    // Check allowance
        balanceOf[_from] -= _value;                          // Subtract from the sender
        totalSupply -= _value;                               // Updates totalSupply
        Burn(_from, _value);
        return true;
    }
}