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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to a potential ITokenReceiver interface before updating the allowance. This creates a classic CEI (Check-Effects-Interactions) pattern violation where:
 * 
 * 1. **Multi-Transaction Setup**: An attacker must first set up allowance in a separate transaction
 * 2. **Stateful Exploitation**: The vulnerability exploits the persistent allowance state across transactions
 * 3. **Reentrancy Window**: The external call occurs after balance updates but before allowance updates, creating a reentrancy window
 * 
 * **Exploitation Scenario:**
 * - Transaction 1: Attacker gets approval for X tokens from victim
 * - Transaction 2: Attacker calls transferFrom, which triggers onTokenReceived callback
 * - During callback: Attacker re-enters transferFrom again before allowance is decremented
 * - Result: Attacker can drain more tokens than originally approved by exploiting the persistent allowance state
 * 
 * The vulnerability requires multiple transactions because:
 * 1. Initial allowance setup must happen in a separate transaction
 * 2. The reentrancy exploitation depends on the accumulated allowance state from previous transactions
 * 3. Each reentrant call can potentially transfer the full allowance amount before it gets decremented
 * 
 * This is realistic as many modern token standards include callback mechanisms for recipient notification, making this a subtle but dangerous vulnerability pattern.
 */
pragma solidity ^0.4.8;
contract tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData); }

// Added interface definition for ITokenReceiver matching the external call
interface ITokenReceiver {
    function onTokenReceived(address from, uint256 value, address operator) external;
}

contract ISE {
    /* Public variables of the token */
    string public standard;
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
    function ISE() {
        balanceOf[msg.sender] =  1000000000 * 1000000000000000000;              // Give the creator all initial tokens
        totalSupply =  1000000000 * 1000000000000000000;                        // Update total supply
        standard = "ERC20";
        name = "ISE";                                   // Set the name for display purposes
        symbol = "ISE";                               // Set the symbol for display purposes
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
        
        // Update balances first
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balanceOf[_from] -= _value;                           // Subtract from the sender
        balanceOf[_to] += _value;                             // Add the same to the recipient
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // External call to notify recipient - REENTRANCY VULNERABILITY
        if (isContract(_to)) {
            // Note: no try-catch in Solidity 0.4.x, external call instead
            // Failures are ignored
            ITokenReceiver(_to).onTokenReceived(_from, _value, msg.sender);
        }
        
        // VULNERABLE: Allowance update happens AFTER external call
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        allowance[_from][msg.sender] -= _value;
        Transfer(_from, _to, _value);
        return true;
    }

    // Helper for contract detection in 0.4.x
    function isContract(address addr) internal constant returns (bool) {
        uint size;
        assembly { size := extcodesize(addr) }
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
