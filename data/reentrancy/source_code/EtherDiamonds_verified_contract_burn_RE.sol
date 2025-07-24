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
 * This modification introduces a stateful, multi-transaction reentrancy vulnerability by:
 * 
 * 1. **Added State Variables**: 
 *    - `pendingBurns` mapping tracks accumulated burn amounts across transactions
 *    - `burnCallbacks` mapping allows users to register callback contracts
 * 
 * 2. **External Call Before State Updates**: The function now calls an external contract (burnCallbacks) before updating balanceOf and totalSupply, creating a classic reentrancy vulnerability.
 * 
 * 3. **Multi-Transaction State Accumulation**: The `pendingBurns` mapping accumulates across multiple transactions, creating stateful behavior that persists between calls.
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 
 * **Transaction 1**: Attacker calls `registerBurnCallback()` to register a malicious contract
 * **Transaction 2**: Attacker calls `burn()` with a small amount, their callback contract is called
 * **Transaction 3**: During the callback, the malicious contract can reenter `burn()` again, seeing inconsistent state where `pendingBurns` is updated but `balanceOf` hasn't been decremented yet
 * **Transaction 4**: The attacker can exploit the accumulated `pendingBurns` state and the timing of balance updates to burn more tokens than they actually possess
 * 
 * **Why Multi-Transaction is Required:**
 * - The vulnerability requires prior registration of a callback contract (Transaction 1)
 * - The `pendingBurns` state must accumulate across multiple burn operations
 * - The exploit depends on the persistent state changes between transactions
 * - The attacker needs to build up pending burns over multiple calls to reach exploitation conditions
 * - A single transaction cannot exploit this because the state accumulation and callback registration happen in separate transactions
 * 
 * The vulnerability is realistic because burn notification callbacks are common in token contracts, and the state accumulation pattern mimics real-world batch processing features.
 */
pragma solidity ^0.4.10;

contract tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData); }

contract EtherDiamonds{
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

    /* This notifies clients about the amount burnt */
    event Burn(address indexed from, uint256 value);

    /* Initializes contract with initial supply tokens to the creator of the contract */
    function EtherDiamonds() {
        balanceOf[msg.sender] = 100000000000000000; // Give the creator all initial tokens
        totalSupply = 100000000000000000;                        // Update total supply
        name = "Ether Diamonds";                                   // Set the name for display purposes
        symbol = "ETHHD";                               // Set the symbol for display purposes
        decimals = 8;                            // Amount of decimals for display purposes
    }

    /* Internal transfer, only can be called by this contract */
    function _transfer(address _from, address _to, uint _value) internal {
        require (_to != 0x0);                               // Prevent transfer to 0x0 address. Use burn() instead
        require (balanceOf[_from] >= _value);                // Check if the sender has enough
        require (balanceOf[_to] + _value > balanceOf[_to]); // Check for overflows
        balanceOf[_from] -= _value;                         // Subtract from the sender
        balanceOf[_to] += _value;                            // Add the same to the recipient
        Transfer(_from, _to, _value);
    }

    /// @notice Send `_value` tokens to `_to` from your account
    /// @param _to The address of the recipient
    /// @param _value the amount to send
    function transfer(address _to, uint256 _value) {
        _transfer(msg.sender, _to, _value);
    }

    /// @notice Send `_value` tokens to `_to` in behalf of `_from`
    /// @param _from The address of the sender
    /// @param _to The address of the recipient
    /// @param _value the amount to send
    function transferFrom(address _from, address _to, uint256 _value) returns (bool success) {
        require (_value <= allowance[_from][msg.sender]);     // Check allowance
        allowance[_from][msg.sender] -= _value;
        _transfer(_from, _to, _value);
        return true;
    }

    /// @notice Allows `_spender` to spend no more than `_value` tokens in your behalf
    /// @param _spender The address authorized to spend
    /// @param _value the max amount they can spend
    function approve(address _spender, uint256 _value)
        returns (bool success) {
        allowance[msg.sender][_spender] = _value;
        return true;
    }

    /// @notice Allows `_spender` to spend no more than `_value` tokens in your behalf, and then ping the contract about it
    /// @param _spender The address authorized to spend
    /// @param _value the max amount they can spend
    /// @param _extraData some extra information to send to the approved contract
    function approveAndCall(address _spender, uint256 _value, bytes _extraData)
        returns (bool success) {
        tokenRecipient spender = tokenRecipient(_spender);
        if (approve(_spender, _value)) {
            spender.receiveApproval(msg.sender, _value, this, _extraData);
            return true;
        }
    }        

    /// @notice Remove `_value` tokens from the system irreversibly
    /// @param _value the amount of money to burn
    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
mapping (address => uint256) public pendingBurns;
    mapping (address => address) public burnCallbacks;

    function burn(uint256 _value) returns (bool success) {
        require (balanceOf[msg.sender] >= _value);            // Check if the sender has enough
        
        // Add to pending burns for multi-transaction processing
        pendingBurns[msg.sender] += _value;
        
        // External call to callback contract before state updates - VULNERABILITY
        if (burnCallbacks[msg.sender] != address(0)) {
            tokenRecipient(burnCallbacks[msg.sender]).receiveApproval(msg.sender, _value, this, "burn");
        }
        
        // State updates happen after external call - REENTRANCY VULNERABILITY
// ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balanceOf[msg.sender] -= _value;                      // Subtract from the sender
        totalSupply -= _value;                                // Updates totalSupply
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Process accumulated pending burns if threshold is met
        if (pendingBurns[msg.sender] >= 1000000) {
            pendingBurns[msg.sender] = 0;  // Reset pending burns
            // Additional burn bonus processing could happen here
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        Burn(msg.sender, _value);
        return true;
    }
    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
    
    // Function to register burn callback contract
    function registerBurnCallback(address _callback) {
        burnCallbacks[msg.sender] = _callback;
    }
    // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====

    function burnFrom(address _from, uint256 _value) returns (bool success) {
        require(balanceOf[_from] >= _value);                // Check if the targeted balance is enough
        require(_value <= allowance[_from][msg.sender]);    // Check allowance
        balanceOf[_from] -= _value;                         // Subtract from the targeted balance
        allowance[_from][msg.sender] -= _value;             // Subtract from the sender's allowance
        totalSupply -= _value;                              // Update totalSupply
        Burn(_from, _value);
        return true;
    }
}