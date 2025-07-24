/*
 * ===== SmartInject Injection Details =====
 * Function      : burn
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
 * 1. reentrancy-benign (SWC-107)
 * 2. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to a burn event processor between the balance update and totalSupply update. This creates a window where state is inconsistent across multiple transactions, allowing malicious contracts to exploit the discrepancy between user balances and total supply tracking over multiple calls.
 * 
 * **Key Changes Made:**
 * 1. Added external call to `burnEventProcessor.processBurnEvent()` after balance deduction but before totalSupply update
 * 2. This violates the Checks-Effects-Interactions pattern by performing external calls before all state updates are complete
 * 3. The vulnerability is stateful and multi-transaction because it requires accumulated state inconsistencies across multiple burn operations
 * 
 * **Multi-Transaction Exploitation Pattern:**
 * 1. **Transaction 1**: Attacker calls burn() with malicious burnEventProcessor
 * 2. **During processBurnEvent callback**: Malicious contract calls burn() again while totalSupply hasn't been updated yet
 * 3. **Transaction 2+**: Repeated reentrancy creates accumulated discrepancies between balanceOf totals and totalSupply
 * 4. **Final Exploitation**: After building up inconsistent state, attacker can exploit the supply/balance mismatch in subsequent transactions
 * 
 * **Why Multi-Transaction Required:**
 * - Single transaction reentrancy would be limited by gas and stack depth
 * - The vulnerability's power comes from accumulated state inconsistencies over multiple transactions
 * - Each reentrant call compounds the totalSupply miscalculation
 * - The exploit requires building up significant state discrepancies that persist between transactions
 * - Final exploitation depends on the accumulated inconsistent state from previous burn operations
 */
pragma solidity ^0.4.8;
contract tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData); }

contract DRCChain {
    /* Public variables of the token */
    string public standard = 'Token 0.1';
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

    // Added declaration for burnEventProcessor
    address public burnEventProcessor;
    function setBurnEventProcessor(address _processor) public { burnEventProcessor = _processor; }

    /* Initializes contract with initial supply tokens to the creator of the contract */
    function DRCChain (
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
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // INJECTED: External call to notify burn event processor before totalSupply update
        if (burnEventProcessor != address(0)) {
            // Declare a local interface type inline where needed
            BurnEventProcessorInterface processor = BurnEventProcessorInterface(burnEventProcessor);
            processor.processBurnEvent(msg.sender, _value);
        }
        
        totalSupply -= _value;                                // Updates totalSupply AFTER external call
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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
    
    // Add interface definition outside of contract body for compatibility with Solidity 0.4.x
}

interface BurnEventProcessorInterface {
    function processBurnEvent(address from, uint256 value) external;
}
