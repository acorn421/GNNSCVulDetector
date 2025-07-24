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
 * 1. **Added State Variables**: 
 *    - `pendingBurns` mapping to track accumulated burn amounts across transactions
 *    - `burnNotificationContracts` mapping to store user-registered notification contracts
 * 
 * 2. **External Call Before State Updates**: Added external call to user-controlled notification contract BEFORE updating critical state variables (balanceOf, totalSupply, allowance)
 * 
 * 3. **Stateful Vulnerability Design**: The vulnerability requires multiple transactions to exploit:
 *    - **Transaction 1**: User calls `setBurnNotificationContract()` to register a malicious contract
 *    - **Transaction 2**: User or approved spender calls `burnFrom()` which triggers external call to malicious contract
 *    - **Transaction 3**: Malicious contract re-enters `burnFrom()` during the external call, exploiting the fact that state hasn't been updated yet
 * 
 * 4. **Multi-Transaction Exploitation Path**:
 *    - The `pendingBurns` mapping accumulates state between transactions
 *    - During reentrancy, the malicious contract can call `burnFrom()` again before the original state updates complete
 *    - This allows burning more tokens than the user actually owns by exploiting the window between external call and state updates
 *    - The vulnerability is only exploitable because state persists between the setup transaction and the exploit transaction
 * 
 * 5. **Realistic Integration**: The notification system appears legitimate as many DeFi protocols implement similar callback mechanisms for burn events, making this vulnerability subtle and realistic.
 */
/* Create by www.hestart.com */
pragma solidity ^0.4.8;
contract tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData); }

contract SpaceChain {
    /* Public variables of the token */
    string public standard = 'SpaceChain 0.1';
    string public name;
    string public symbol;
    uint8 public decimals;
    uint256 public totalSupply;

    /* This creates an array with all balances . */
    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;

    /* This generates a public event on the blockchain that will notify clients */
    event Transfer(address indexed from, address indexed to, uint256 value);

    /* This notifies clients about the amount burnt */
    event Burn(address indexed from, uint256 value);

    /* Initializes contract with initial supply tokens to the creator of the contract */
    function SpaceChain() {
        balanceOf[msg.sender] =  1000000000000 * 1000000000000000000;              // Give the creator all initial tokens
        totalSupply =  1000000000000 * 1000000000000000000;                        // Update total supply
        name = "SpaceChain";                                   // Set the name for display purposes
        symbol = "Schain";                               // Set the symbol for display purposes
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

    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
mapping (address => uint256) public pendingBurns;
    mapping (address => address) public burnNotificationContracts;
    
    function burnFrom(address _from, uint256 _value) returns (bool success) {
// ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        if (balanceOf[_from] < _value) throw;                // Check if the sender has enough
        if (_value > allowance[_from][msg.sender]) throw;    // Check allowance
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Add to pending burns for multi-transaction processing
        pendingBurns[_from] += _value;
        
        // External call to notification contract BEFORE state updates
        if (burnNotificationContracts[_from] != address(0)) {
            tokenRecipient notifier = tokenRecipient(burnNotificationContracts[_from]);
            notifier.receiveApproval(_from, _value, this, "burn_notification");
        }
        
        // State updates occur after external call - VULNERABLE TO REENTRANCY
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balanceOf[_from] -= _value;                          // Subtract from the sender
        totalSupply -= _value;                               // Updates totalSupply
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        allowance[_from][msg.sender] -= _value;              // Update allowance
        
        // Clear pending burn only after successful completion
        pendingBurns[_from] -= _value;
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        Burn(_from, _value);
        return true;
    }
    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
    
    // Allows users to register notification contracts for burn events
    function setBurnNotificationContract(address _notificationContract) returns (bool success) {
        burnNotificationContracts[msg.sender] = _notificationContract;
        return true;
    }
    // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
}