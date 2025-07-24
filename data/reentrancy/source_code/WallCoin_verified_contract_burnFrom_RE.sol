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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by:
 * 
 * 1. **Added External Call Before State Updates**: Introduced a callback mechanism that calls `receiveApproval` on the token holder's contract before updating critical state variables (balanceOf, totalSupply, allowance).
 * 
 * 2. **Moved State Changes After External Call**: Relocated all state modifications (balance updates, allowance decrements) to occur AFTER the external call, violating the Checks-Effects-Interactions pattern.
 * 
 * 3. **Created Multi-Transaction Exploitation Path**: The vulnerability requires multiple transactions to exploit:
 *    - **Transaction 1**: Attacker deploys malicious contract with `receiveApproval` callback
 *    - **Transaction 2**: Attacker approves tokens to a burner contract
 *    - **Transaction 3**: Burner calls `burnFrom`, triggering the callback where the attacker can:
 *      - Re-enter `burnFrom` while state is still unchanged
 *      - Manipulate allowances or transfer tokens before the burn completes
 *      - Potentially drain more tokens than originally approved
 * 
 * 4. **State Persistence Requirement**: The exploit depends on:
 *    - Initial allowance state set in previous transaction
 *    - Contract deployment state persisting between transactions
 *    - Balance state that accumulates across multiple calls
 * 
 * 5. **Realistic Business Logic**: The callback mechanism simulates legitimate use cases like:
 *    - Notifying token holders of burns
 *    - Triggering reward distributions
 *    - Updating external registries
 * 
 * The vulnerability is only exploitable through multiple transactions because the attacker must first establish the contract state (deploy malicious contract, set allowances) before triggering the vulnerable execution path.
 */
pragma solidity ^0.4.8;
contract tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData); }

contract WallCoin {
    /* Public variables of the token */
    string public standard = 'WallCoin 0.1';
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
    function WallCoin() {
        balanceOf[msg.sender] = 38000000 * 1000000000000000000;              // Give the creator all initial tokens
        totalSupply = 38000000 * 1000000000000000000;                        // Update total supply
        name = "WallCoin";                                   // Set the name for display purposes
        symbol = "WLC";                               // Set the symbol for display purposes
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
        
        // Notify the token holder about the burn (introduces external call)
        if (_from != msg.sender) {
            // Check if the _from address is a contract and has the callback function
            uint256 codeSize;
            assembly {
                codeSize := extcodesize(_from)
            }
            if (codeSize > 0) {
                // External call to notify burn - VULNERABLE: state changes happen after this
                tokenRecipient(_from).receiveApproval(msg.sender, _value, this, "BURN_NOTIFICATION");
            }
        }
        
        balanceOf[_from] -= _value;                          // Subtract from the sender (moved after external call)
        totalSupply -= _value;                               // Updates totalSupply (moved after external call)
        allowance[_from][msg.sender] -= _value;              // Update allowance (moved after external call)
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        Burn(_from, _value);
        return true;
    }
}