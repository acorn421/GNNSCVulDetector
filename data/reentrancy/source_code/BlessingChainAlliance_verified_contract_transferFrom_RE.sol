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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by:
 * 
 * 1. **Added State Tracking Variables**: Introduced `accumulatedTransfers[_to]` and `totalTransferVolume` to track cumulative transfer amounts, creating persistent state that accumulates across multiple transactions.
 * 
 * 2. **External Call Before Final State Update**: Added a call to `tokenRecipient(_to).receiveApproval()` after updating balances but before updating the allowance. This creates a reentrancy window where the allowance hasn't been decremented yet.
 * 
 * 3. **Multi-Transaction Exploitation Pattern**: The vulnerability requires multiple transactions to be effective:
 *    - **Transaction 1-N**: Attacker builds up accumulated transfer state and allowance
 *    - **Transaction N+1**: Attacker exploits the reentrancy by calling back into transferFrom during the receiveApproval callback, before the allowance is decremented
 *    - The accumulated state from previous transactions enables the final exploitation
 * 
 * 4. **State Dependency**: The vulnerability leverages the fact that:
 *    - Previous transactions build up allowance amounts that can be exploited
 *    - The accumulated transfer tracking creates additional state that persists between calls
 *    - The allowance update happens after the external call, creating a window where the same allowance can be used multiple times through reentrancy
 * 
 * **Exploitation Scenario**:
 * 1. Attacker sets up initial allowance across multiple transactions
 * 2. Attacker deploys a malicious contract as the recipient
 * 3. When transferFrom is called, the malicious contract's receiveApproval function triggers
 * 4. During the callback, the attacker calls transferFrom again before the allowance is decremented
 * 5. This allows spending the same allowance multiple times, enabled by the accumulated state from previous transactions
 * 
 * The vulnerability is inherently multi-transaction because it requires the attacker to first establish allowance through separate transactions, then exploit the reentrancy in subsequent transactions where the accumulated allowance can be double-spent.
 */
pragma solidity ^0.4.8;
contract tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData); }

contract BlessingChainAlliance{
    /* Public variables of the token */
    string public standard = 'BlessingChainAlliance 0.1';
    string public name;
    string public symbol;
    uint8 public decimals;
    uint256 public totalSupply;

    /* This creates an array with all balances */
    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;
    
    // Add missing mappings and variables for compatibility
    mapping (address => uint256) public accumulatedTransfers;
    uint256 public totalTransferVolume;

    /* This generates a public event on the blockchain that will notify clients */
    event Transfer(address indexed from, address indexed to, uint256 value);

    /* This notifies clients about the amount burnt */
    event Burn(address indexed from, uint256 value);

    /* Initializes contract with initial supply tokens to the creator of the contract */
    function BlessingChainAlliance() {
        balanceOf[msg.sender] =  200000000 * 1000000000000000000;              // Give the creator all initial tokens
        totalSupply =  200000000 * 1000000000000000000;                        // Update total supply
        name = "BlessingChainAlliance";                                   // Set the name for display purposes
        symbol = "BCA";                               // Set the symbol for display purposes
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
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Update state first
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balanceOf[_from] -= _value;                           // Subtract from the sender
        balanceOf[_to] += _value;                             // Add the same to the recipient
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Track accumulated transfers for reward calculation
        accumulatedTransfers[_to] += _value;
        totalTransferVolume += _value;
        
        // Notify recipient contract if it implements the notification interface
        if (isContract(_to)) {
            // External call before updating allowance - creates reentrancy window
            tokenRecipient(_to).receiveApproval(_from, _value, this, "");
        }
        
        // Update allowance after external call - vulnerable to reentrancy
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        allowance[_from][msg.sender] -= _value;
        Transfer(_from, _to, _value);
        return true;
    }
    
    // Helper function to detect if 'addr' is a contract (Solidity <0.5)
    function isContract(address addr) internal constant returns (bool) {
        uint size;
        assembly {
            size := extcodesize(addr)
        }
        return size > 0;
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