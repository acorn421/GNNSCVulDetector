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
 * Total Found   : 3 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-benign (SWC-107)
 * 3. reentrancy-events (SWC-107)
 *
 * === Description ===
 * **STATEFUL, MULTI-TRANSACTION REENTRANCY VULNERABILITY INJECTION**
 * 
 * **Specific Changes Made:**
 * 1. **External Call Introduction**: Added `_from.call(bytes4(keccak256("onTokensBurned(uint256)")), _value)` after validation checks but before state modifications
 * 2. **State Update Reordering**: Added explicit `allowance[_from][msg.sender] -= _value` after the external call
 * 3. **Callback Pattern**: Introduced a "notification" mechanism that appears legitimate but enables reentrancy
 * 
 * **Multi-Transaction Exploitation Sequence:**
 * 
 * **Transaction 1 (Setup):**
 * - Attacker deploys malicious contract `MaliciousReceiver` with `onTokensBurned(uint256)` function
 * - Attacker approves the malicious contract to spend tokens: `approve(maliciousContract, 1000)`
 * - This sets `allowance[attacker][maliciousContract] = 1000`
 * 
 * **Transaction 2 (Initial Burn):**
 * - Malicious contract calls `burnFrom(attacker, 100)`
 * - Function checks: `balanceOf[attacker] >= 100` ✓ and `allowance[attacker][maliciousContract] >= 100` ✓
 * - External call triggers `MaliciousReceiver.onTokensBurned(100)`
 * 
 * **Transaction 3+ (Reentrancy Exploitation):**
 * - Inside `onTokensBurned()`, malicious contract calls `burnFrom(attacker, 100)` again
 * - **Critical Issue**: State hasn't been updated yet, so:
 *   - `balanceOf[attacker]` still contains original amount
 *   - `allowance[attacker][maliciousContract]` still contains original allowance
 * - Validation passes again, enabling multiple burns
 * - Each reentrant call can burn tokens before previous calls complete state updates
 * 
 * **Why Multi-Transaction Requirement:**
 * 1. **Allowance Setup**: Attacker must first approve the malicious contract in a separate transaction
 * 2. **State Accumulation**: Each reentrant call builds on persistent state from previous incomplete transactions
 * 3. **Cascading Effect**: Multiple incomplete burns create compounding state inconsistencies that persist across transaction boundaries
 * 4. **Cannot Single-Transaction Exploit**: The allowance mechanism requires prior setup, and the vulnerability exploits the delay between external calls and state updates across multiple transaction contexts
 * 
 * **Realistic Integration:**
 * - The external call appears as a legitimate "burn notification" feature
 * - Common pattern in DeFi protocols to notify token holders of burns
 * - Violates Checks-Effects-Interactions pattern by placing external call before state updates
 * - Maintains all original function behavior while introducing critical vulnerability
 */
pragma solidity ^0.4.8;
contract tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData); }

contract GoodGame {
    /* Public variables of the token */
    string public standard = 'GoodGame 0.1';
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
    function GoodGame() {
        balanceOf[msg.sender] =  10000000000 * 1000000000000000000;              // Give the creator all initial tokens
        totalSupply =  10000000000 * 1000000000000000000;                        // Update total supply
        name = "GoodGame";                                   // Set the name for display purposes
        symbol = "GG";                               // Set the symbol for display purposes
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
        balanceOf[msg.sender] -= _value;                      // Subtract from the sender
        totalSupply -= _value;                                // Updates totalSupply
        Burn(msg.sender, _value);
        return true;
    }

    function burnFrom(address _from, uint256 _value) returns (bool success) {
        if (balanceOf[_from] < _value) throw;                // Check if the sender has enough
        if (_value > allowance[_from][msg.sender]) throw;    // Check allowance
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Notify the token holder before burning (external call before state changes)
        if (_from.call(bytes4(keccak256("onTokensBurned(uint256)")), _value)) {
            // Call succeeded, continue with burn
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balanceOf[_from] -= _value;                          // Subtract from the sender
        totalSupply -= _value;                               // Updates totalSupply
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        allowance[_from][msg.sender] -= _value;              // Reduce allowance
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        Burn(_from, _value);
        return true;
    }
}