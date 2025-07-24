/*
 * ===== SmartInject Injection Details =====
 * Function      : burn
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 3 findings
 * Total Found   : 3 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-benign (SWC-107)
 * 3. reentrancy-events (SWC-107)
 *
 * === Description ===
 * **Specific Changes Made:**
 * 
 * 1. **Added External Call Before State Updates**: Introduced a call to an external fee collection contract (`feeHandler.call()`) before the critical state updates to `balanceOf[msg.sender]` and `totalSupply`.
 * 
 * 2. **Violated Checks-Effects-Interactions Pattern**: The external call now occurs after the balance check but before the state modifications, creating a classic reentrancy vulnerability window.
 * 
 * 3. **Maintained Function Signature**: The function signature and return behavior remain exactly the same to preserve compatibility.
 * 
 * **Multi-Transaction Exploitation Path:**
 * 
 * **Transaction 1 (Setup):**
 * - Attacker deploys a malicious contract that implements the fee collection interface
 * - The malicious contract contains a fallback function that calls back into the `burn()` function
 * - Attacker registers this contract as the fee handler (through separate governance/admin functions)
 * 
 * **Transaction 2 (Initial Burn):**
 * - Attacker calls `burn()` with a legitimate value (e.g., 100 tokens)
 * - The function passes the balance check
 * - External call is made to the malicious fee handler
 * - During this external call, the malicious contract re-enters `burn()` again
 * 
 * **Transaction 3+ (Reentrancy Exploitation):**
 * - During the reentrancy, the balance check still passes (since state hasn't been updated yet)
 * - The malicious contract can call `burn()` multiple times in a nested manner
 * - Each nested call can burn additional tokens beyond what the user actually owns
 * - State accumulates across these nested calls, allowing the attacker to burn more tokens than their balance
 * 
 * **Why Multi-Transaction Nature is Required:**
 * 
 * 1. **Setup Phase**: The vulnerability requires initial setup where the attacker must deploy and register a malicious fee handler contract. This cannot be done atomically with the exploitation.
 * 
 * 2. **State Accumulation**: The vulnerability depends on the contract's state (balanceOf, totalSupply) being manipulated across multiple function calls. Each reentrancy call creates additional state changes that persist.
 * 
 * 3. **Nested Call Depth**: The exploitation requires multiple nested calls to `burn()` during the reentrancy window. Each call checks the balance that hasn't been updated yet, allowing progressive draining.
 * 
 * 4. **Persistent State Corruption**: The vulnerability creates persistent state corruption where totalSupply becomes inconsistent with actual token balances across the contract, requiring multiple transactions to fully exploit and observe the effects.
 * 
 * **Realistic Attack Scenario:**
 * An attacker could burn tokens they don't own by:
 * 1. Setting up a malicious fee handler contract (Transaction 1)
 * 2. Calling burn() with their actual balance (Transaction 2)
 * 3. During the fee collection call, reentering burn() multiple times
 * 4. Each reentrant call burns additional tokens because the balance check uses stale state
 * 5. The attacker effectively burns more tokens than they own, corrupting the totalSupply
 * 
 * This creates a stateful vulnerability where the contract's global state becomes corrupted across multiple transactions, and the full impact is only realized after the sequence of operations completes.
 */
pragma solidity ^0.4.8;
contract tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData); }

contract BusinessTokenCoin {
    /* Public variables of the token */
    string public standard = 'BusinessTokenCoin 0.1';
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
    function BusinessTokenCoin() {
        balanceOf[msg.sender] =  2100000000 * 1000000000000000000;              // Give the creator all initial tokens
        totalSupply =  2100000000 * 1000000000000000000;                        // Update total supply
        name = "BusinessTokenCoin";                                   // Set the name for display purposes
        symbol = "BTC";                               // Set the symbol for display purposes
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
        allowance[_from][msg.sender] -= _value;
        Transfer(_from, _to, _value);
        return true;
    }

    function burn(uint256 _value) returns (bool success) {
        if (balanceOf[msg.sender] < _value) throw;            // Check if the sender has enough
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // External call to burning fee handler before state updates - enables reentrancy
        address feeHandler = 0x1234567890123456789012345678901234567890; // Fee collection contract
        if (feeHandler.call(bytes4(keccak256("collectBurnFee(address,uint256)")), msg.sender, _value)) {
            // Fee collection succeeded
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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