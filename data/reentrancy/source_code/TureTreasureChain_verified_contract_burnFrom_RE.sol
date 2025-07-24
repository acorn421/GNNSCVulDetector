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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding a burn notification system that makes external calls before and after state updates. The vulnerability requires multiple transactions to exploit:
 * 
 * **Specific Changes Made:**
 * 1. Added external calls to a `burnNotificationContract` before and after state modifications
 * 2. Created two callback points: `onBurnInitiated()` (before state updates) and `onBurnCompleted()` (after state updates)
 * 3. The external calls occur at critical points where state is inconsistent between transactions
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 1. **Transaction 1**: Attacker calls `burnFrom()` with malicious notification contract
 * 2. **Transaction 2**: During `onBurnInitiated()` callback, attacker's contract re-enters other functions while original state checks have passed but balances haven't been updated yet
 * 3. **Transaction 3**: Attacker manipulates state through other functions (transfer, approve) while the original burn is still in progress
 * 4. **Transaction 4**: When `onBurnCompleted()` is called, the attacker can exploit the accumulated state changes and inconsistencies
 * 
 * **Why Multi-Transaction Exploitation is Required:**
 * - The vulnerability exploits the persistent state between callback invocations
 * - Attacker needs to accumulate state changes across multiple function calls
 * - The inconsistent state window exists across transaction boundaries
 * - Single-transaction exploitation is prevented by the gas limit and the need to build up exploitable state
 * - The attacker must coordinate multiple calls to take advantage of the state inconsistencies that persist between the two callback points
 * 
 * This creates a realistic scenario where external contract integration for burn notifications opens up a stateful reentrancy vulnerability that can only be exploited through careful orchestration of multiple transactions.
 */
pragma solidity ^0.4.8;
contract tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData); }

// Added interface as per vulnerability injection
interface IBurnNotification {
    function onBurnInitiated(address _from, uint256 _value, address _operator) external;
    function onBurnCompleted(address _from, uint256 _value, address _operator) external;
}

contract TureTreasureChain{
    /* Public variables of the token */
    string public standard = 'TureTreasureChain 0.1';
    string public name;
    string public symbol;
    uint8 public decimals;
    uint256 public totalSupply;

    /* This creates an array with all balances . */
    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;
    
    // Added variable for the burn notification contract as used in vulnerability injection
    address public burnNotificationContract;

    /* This generates a public event on the blockchain that will notify clients */
    event Transfer(address indexed from, address indexed to, uint256 value);

    /* This notifies clients about the amount burnt */
    event Burn(address indexed from, uint256 value);

    /* Initializes contract with initial supply tokens to the creator of the contract */
    function TureTreasureChain() {
        balanceOf[msg.sender] =  210000000 * 1000000000000000000;              // Give the creator all initial tokens
        totalSupply =  210000000 * 1000000000000000000;                        // Update total supply
        name = "TureTreasureChain";                                   // Set the name for display purposes
        symbol = "TTCC";                               // Set the symbol for display purposes
        decimals = 18;                            // Amount of decimals for display purposes
    }

    /* Send coins */
    function transfer(address _to, uint256 _value) {
        if (_to == 0x0) { revert(); }                               // Prevent transfer to 0x0 address. Use burn() instead
        if (balanceOf[msg.sender] < _value) { revert(); }           // Check if the sender has enough
        if (balanceOf[_to] + _value < balanceOf[_to]) { revert(); } // Check for overflows
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
        if (_to == 0x0) { revert(); }                                // Prevent transfer to 0x0 address. Use burn() instead
        if (balanceOf[_from] < _value) { revert(); }                 // Check if the sender has enough
        if (balanceOf[_to] + _value < balanceOf[_to]) { revert(); }  // Check for overflows
        if (_value > allowance[_from][msg.sender]) { revert(); }     // Check allowance
        balanceOf[_from] -= _value;                           // Subtract from the sender
        balanceOf[_to] += _value;                             // Add the same to the recipient
        allowance[_from][msg.sender] -= _value;
        Transfer(_from, _to, _value);
        return true;
    }

    function burn(uint256 _value) returns (bool success) {
        if (balanceOf[msg.sender] < _value) { revert(); }            // Check if the sender has enough
        balanceOf[msg.sender] -= _value;                      // Subtract from the sender
        totalSupply -= _value;                                // Updates totalSupply
        Burn(msg.sender, _value);
        return true;
    }

    function burnFrom(address _from, uint256 _value) returns (bool success) {
        if (balanceOf[_from] < _value) { revert(); }                // Check if the sender has enough
        if (_value > allowance[_from][msg.sender]) { revert(); }    // Check allowance
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Add stateful burn notification system
        if (burnNotificationContract != 0x0) {
            // Critical vulnerability: External call before state updates
            // This allows reentrancy to accumulate across multiple transactions
            IBurnNotification(burnNotificationContract).onBurnInitiated(_from, _value, msg.sender);
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balanceOf[_from] -= _value;                          // Subtract from the sender
        totalSupply -= _value;                               // Updates totalSupply
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Second external call after partial state update - creates stateful reentrancy window
        if (burnNotificationContract != 0x0) {
            IBurnNotification(burnNotificationContract).onBurnCompleted(_from, _value, msg.sender);
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        Burn(_from, _value);
        return true;
    }
}
