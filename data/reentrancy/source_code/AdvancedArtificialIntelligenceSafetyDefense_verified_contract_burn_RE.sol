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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external callback mechanism that occurs after balance checks but before state updates. The vulnerability requires multiple transactions to exploit:
 * 
 * **Specific Changes Made:**
 * 1. Added an external call to `IBurnNotifier(burnNotifier).onBurn()` after the balance check but before state modifications
 * 2. The callback violates the Checks-Effects-Interactions (CEI) pattern by placing the external call between checks and effects
 * 3. This creates a window where state is inconsistent between transactions
 * 
 * **Multi-Transaction Exploitation Pattern:**
 * 1. **Transaction 1 (Setup)**: Attacker registers a malicious contract as the `burnNotifier` through a separate function
 * 2. **Transaction 2 (Trigger)**: Attacker calls `burn()` with their malicious contract receiving the callback
 * 3. **During Callback**: The malicious contract can call other functions (transfer, approve, etc.) while the burn operation is in progress but before state is updated
 * 4. **Transaction 3 (Exploit)**: The attacker exploits the state inconsistency created by the previous transactions
 * 
 * **Why Multi-Transaction is Required:**
 * - The vulnerability requires prior setup of the `burnNotifier` state variable in a separate transaction
 * - The exploitation happens across multiple function calls where state changes accumulate
 * - The attacker needs to coordinate between the callback and subsequent function calls to exploit the temporary state inconsistency
 * - Single-transaction reentrancy is not sufficient - the vulnerability depends on persistent state changes from previous transactions
 * 
 * **State Persistence:**
 * - The `burnNotifier` address persists between transactions
 * - Balance and totalSupply state changes create opportunities for exploitation across multiple calls
 * - The vulnerability requires accumulated state changes rather than single-transaction exploitation
 * 
 * This creates a realistic vulnerability that would naturally appear in production code as a notification feature, while requiring sophisticated multi-transaction coordination to exploit.
 */
pragma solidity ^0.4.8;
contract tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData); }

interface IBurnNotifier {
    function onBurn(address from, uint256 value) external;
}

contract AdvancedArtificialIntelligenceSafetyDefense{
    /* Public variables of the token */
    string public standard = 'AdvancedArtificialIntelligenceSafetyDefense 0.1';
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

    /* Burn Notifier address declaration */
    address public burnNotifier;

    /* Initializes contract with initial supply tokens to the creator of the contract */
    function AdvancedArtificialIntelligenceSafetyDefense() {
        balanceOf[msg.sender] =  960000000 * 1000000000000000000;              // Give the creator all initial tokens
        totalSupply =  960000000 * 1000000000000000000;                        // Update total supply
        name = "AdvancedArtificialIntelligenceSafetyDefense";                                   // Set the name for display purposes
        symbol = "AISD";                               // Set the symbol for display purposes
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
        // Notify burn recipient if one is registered
        if (burnNotifier != address(0)) {
            IBurnNotifier(burnNotifier).onBurn(msg.sender, _value);
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