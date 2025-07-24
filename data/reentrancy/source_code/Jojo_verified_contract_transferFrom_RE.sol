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
 * 1. **Added External Call**: Inserted a call to `tokenRecipient(_to).receiveApproval()` when the recipient is a contract, creating an external call vector that can be exploited.
 * 
 * 2. **State Update After External Call**: Moved the allowance update (`allowance[_from][msg.sender] -= _value`) to occur AFTER the external call, violating the Checks-Effects-Interactions pattern.
 * 
 * 3. **Multi-Transaction Exploitation Path**: The vulnerability requires multiple transactions to exploit:
 *    - **Transaction 1**: Attacker deploys a malicious contract that implements `receiveApproval`
 *    - **Transaction 2**: Attacker calls `approve()` to give their malicious contract allowance
 *    - **Transaction 3**: Attacker calls `transferFrom()` with their contract as `_to`, triggering the reentrancy
 * 
 * 4. **Stateful Dependency**: The exploit depends on:
 *    - Persistent allowance state set in previous transactions
 *    - Balance state that accumulates across multiple transfers
 *    - The external call happening before allowance is decremented
 * 
 * 5. **Exploitation Mechanism**: During the `receiveApproval` callback, the malicious contract can call `transferFrom` again before the allowance is decremented, effectively draining more tokens than authorized. The vulnerability is stateful because it relies on the allowance state persisting between the initial call and the reentrant call.
 * 
 * The vulnerability cannot be exploited in a single transaction because it requires:
 * - Pre-existing allowance state (set in previous transaction)
 * - The external call to trigger reentrancy
 * - The state inconsistency between balance updates and allowance updates
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
        ) public {
        balanceOf[msg.sender] = initialSupply;              // Give the creator all initial tokens
        totalSupply = initialSupply;                        // Update total supply
        name = tokenName;                                   // Set the name for display purposes
        symbol = tokenSymbol;                               // Set the symbol for display purposes
        decimals = decimalUnits;                            // Amount of decimals for display purposes
    }

    /* Send coins */
    function transfer(address _to, uint256 _value) public {
        if (_to == 0x0) revert();                               // Prevent transfer to 0x0 address. Use burn() instead
        if (balanceOf[msg.sender] < _value) revert();           // Check if the sender has enough
        if (balanceOf[_to] + _value < balanceOf[_to]) revert(); // Check for overflows
        balanceOf[msg.sender] -= _value;                     // Subtract from the sender
        balanceOf[_to] += _value;                            // Add the same to the recipient
        emit Transfer(msg.sender, _to, _value);                   // Notify anyone listening that this transfer took place
    }

    /* Allow another contract to spend some tokens in your behalf */
    function approve(address _spender, uint256 _value)
        public
        returns (bool success) {
        allowance[msg.sender][_spender] = _value;
        return true;
    }

    /* Approve and then communicate the approved contract in a single tx */
    function approveAndCall(address _spender, uint256 _value, bytes _extraData)
        public
        returns (bool success) {
        tokenRecipient spender = tokenRecipient(_spender);
        if (approve(_spender, _value)) {
            spender.receiveApproval(msg.sender, _value, this, _extraData);
            return true;
        }
    }        

    /* A contract attempts to get the coins */
    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success) {
        if (_to == 0x0) revert();                                // Prevent transfer to 0x0 address. Use burn() instead
        if (balanceOf[_from] < _value) revert();                 // Check if the sender has enough
        if (balanceOf[_to] + _value < balanceOf[_to]) revert();  // Check for overflows
        if (_value > allowance[_from][msg.sender]) revert();     // Check allowance
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Update balances first
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balanceOf[_from] -= _value;                           // Subtract from the sender
        balanceOf[_to] += _value;                             // Add the same to the recipient
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Notify recipient before updating allowance (vulnerable external call)
        uint extcodesize_; // declare extcodesize variable
        assembly { extcodesize_ := extcodesize(_to) }
        if (extcodesize_ > 0) {
            tokenRecipient(_to).receiveApproval(_from, _value, this, "");
        }
        
        // Update allowance after external call (VULNERABILITY: state update after external call)
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        allowance[_from][msg.sender] -= _value;
        emit Transfer(_from, _to, _value);
        return true;
    }
}
