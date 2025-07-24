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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the recipient address after balance updates. The vulnerability works as follows:
 * 
 * **Specific Changes Made:**
 * 1. Added an external call using `_to.call.value(0)()` to invoke `onTokenReceived(address,uint256)` on the recipient
 * 2. Placed this call AFTER the balance updates but BEFORE the Transfer event
 * 3. The call allows the recipient to execute code while the transfer is in an intermediate state
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 1. **Transaction 1:** Attacker contract calls transfer() to send tokens to itself
 * 2. **During Transaction 1:** The external call triggers the attacker's `onTokenReceived` function
 * 3. **Reentrancy Window:** The attacker can now call transfer() again while the first call is still executing
 * 4. **Transaction 2 (Reentrant):** The second call sees the updated balances from the first call and can exploit this state
 * 5. **State Accumulation:** Multiple reentrant calls can drain more tokens than the original sender had
 * 
 * **Why Multiple Transactions Are Required:**
 * - The vulnerability requires the recipient to have code that can be called back (not possible in a single EOA transfer)
 * - The attacker must deploy a malicious contract that implements the callback
 * - The exploit depends on the accumulated state changes from multiple nested calls
 * - Each reentrant call builds upon the state modifications from previous calls
 * - The attacker needs to set up the attack across multiple transactions: deploy malicious contract, fund it, then execute the reentrancy attack
 * 
 * **Realistic Nature:**
 * This follows real-world patterns like ERC777 token standards that include recipient notifications, making it a realistic vulnerability that could appear in production code attempting to implement advanced token features.
 */
pragma solidity ^0.4.8;
contract tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData); }

contract Jojo {
    /* Public variables of the token */
    string public name;
    string public symbol;
    uint8 public decimals;
    uint256 public totalSupply;

    /* This creates an array with all balances */
    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;

    /* This generates a public event on the blockchain that will notify clients */
    event Transfer(address indexed from, address indexed to, uint256 value);

    /* Initializes contract with initial supply tokens to the creator of the contract */
    function Jojo(
        uint256 initialSupply,
        string tokenName,
        uint8 decimalUnits,
        string tokenSymbol
        ) {
        balanceOf[msg.sender] = initialSupply;              // Give the creator all initial tokens
        totalSupply = initialSupply;                        // Update total supply
        name = tokenName;                                   // Set the name for display purposes
        symbol = tokenSymbol;                               // Set the symbol for display purposes
        decimals = decimalUnits;                            // Amount of decimals for display purposes
    }

    /* Send coins */
    function transfer(address _to, uint256 _value) {
        if (_to == 0x0) throw;                               // Prevent transfer to 0x0 address. Use burn() instead
        if (balanceOf[msg.sender] < _value) throw;           // Check if the sender has enough
        if (balanceOf[_to] + _value < balanceOf[_to]) throw; // Check for overflows
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Update balances first
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balanceOf[msg.sender] -= _value;                     // Subtract from the sender
        balanceOf[_to] += _value;                            // Add the same to the recipient
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // VULNERABILITY: External call to recipient after state update but before completion
        // This enables reentrancy where the recipient can call back into transfer()
        if (_to.call.value(0)(bytes4(keccak256("onTokenReceived(address,uint256)")), msg.sender, _value)) {
            // Callback succeeded - this creates a reentrancy window
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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
}