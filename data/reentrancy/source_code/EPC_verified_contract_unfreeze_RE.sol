/*
 * ===== SmartInject Injection Details =====
 * Function      : unfreeze
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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to a user-controlled contract AFTER state updates but BEFORE event emission. The vulnerability requires multiple transactions to exploit:
 * 
 * **Multi-Transaction Exploitation Pattern:**
 * 
 * 1. **Transaction 1 (Setup)**: Attacker calls unfreeze() with a legitimate amount, establishing baseline state
 * 2. **Transaction 2 (Exploit)**: Attacker calls unfreeze() again, triggering the external callback
 * 3. **During Callback**: The callback contract can call unfreeze() again before the original transaction completes, exploiting the state inconsistency
 * 
 * **Why Multi-Transaction:**
 * - The vulnerability relies on accumulated state changes across multiple calls
 * - Each transaction modifies freezeOf and balanceOf mappings that persist between calls
 * - The external callback creates a window for state manipulation that requires the attacker to have already established frozen tokens in previous transactions
 * - Single-transaction exploitation is impossible because the attacker needs existing frozen balance to trigger the initial unfreeze call
 * 
 * **Exploitation Scenario:**
 * 1. Attacker freezes 1000 tokens (separate transaction)
 * 2. Attacker calls unfreeze(500) - this triggers the callback
 * 3. In the callback, attacker calls unfreeze(500) again before the first call completes
 * 4. Both calls succeed because the state check happens before state modification
 * 5. Attacker unfreezes 1000 tokens total while only having 500 legitimately frozen
 * 
 * This creates a realistic vulnerability that requires state accumulation across multiple transactions to be exploitable.
 */
pragma solidity ^0.4.8;

/**
 * Math operations with safety checks
 */
contract SafeMath {
    function safeMul(uint256 a, uint256 b) internal returns (uint256) {
        uint256 c = a * b;
        assert(a == 0 || c / a == b);
        return c;
    }

    function safeDiv(uint256 a, uint256 b) internal returns (uint256) {
        assert(b > 0);
        uint256 c = a / b;
        assert(a == b * c + a % b);
        return c;
    }

    function safeSub(uint256 a, uint256 b) internal returns (uint256) {
        assert(b <= a);
        return a - b;
    }

    function safeAdd(uint256 a, uint256 b) internal returns (uint256) {
        uint256 c = a + b;
        assert(c>=a && c>=b);
        return c;
    }

    function assert(bool assertion) internal {
        if (!assertion) {
            throw;
        }
    }
}
contract EPC is SafeMath{
    string public name;
    string public symbol;
    uint8 public decimals;
    uint256 public totalSupply;
    address public owner;

    /* This creates an array with all balances */
    mapping (address => uint256) public balanceOf;
    mapping (address => uint256) public freezeOf;
    mapping (address => mapping (address => uint256)) public allowance;

    /* This generates a public event on the blockchain that will notify clients */
    event Transfer(address indexed from, address indexed to, uint256 value);

    /* This notifies clients about the amount burnt */
    event Burn(address indexed from, uint256 value);

    /* This notifies clients about the amount frozen */
    event Freeze(address indexed from, uint256 value);

    /* This notifies clients about the amount unfrozen */
    event Unfreeze(address indexed from, uint256 value);

    /* Initializes contract with initial supply tokens to the creator of the contract */
    function EPC(
        uint256 _totalSupply,
        string _name,
        uint8 _decimals,
        string _symbol
    ) {
        balanceOf[msg.sender] = _totalSupply;              // Give the creator all initial tokens
        totalSupply = _totalSupply;                        // Update total supply
        name = _name;                                   // Set the name for display purposes
        symbol = _symbol;                               // Set the symbol for display purposes
        decimals = _decimals;                            // Amount of decimals for display purposes
        owner = msg.sender;
    }

    /* Send coins */
    function transfer(address _to, uint256 _value) {
        if (_to == 0x0) throw;                               // Prevent transfer to 0x0 address. Use burn() instead
        if (_value <= 0) throw;
        if (balanceOf[msg.sender] < _value) throw;           // Check if the sender has enough
        if (balanceOf[_to] + _value < balanceOf[_to]) throw; // Check for overflows
        balanceOf[msg.sender] = SafeMath.safeSub(balanceOf[msg.sender], _value);                     // Subtract from the sender
        balanceOf[_to] = SafeMath.safeAdd(balanceOf[_to], _value);                            // Add the same to the recipient
        Transfer(msg.sender, _to, _value);                   // Notify anyone listening that this transfer took place
    }

    /* Allow another contract to spend some tokens in your behalf */
    function approve(address _spender, uint256 _value)
    returns (bool success) {
        if (_value <= 0) throw;
        allowance[msg.sender][_spender] = _value;
        return true;
    }


    /* A contract attempts to get the coins */
    function transferFrom(address _from, address _to, uint256 _value) returns (bool success) {
        if (_to == 0x0) throw;                                // Prevent transfer to 0x0 address. Use burn() instead
        if (_value <= 0) throw;
        if (balanceOf[_from] < _value) throw;                 // Check if the sender has enough
        if (balanceOf[_to] + _value < balanceOf[_to]) throw;  // Check for overflows
        if (_value > allowance[_from][msg.sender]) throw;     // Check allowance
        balanceOf[_from] = SafeMath.safeSub(balanceOf[_from], _value);                           // Subtract from the sender
        balanceOf[_to] = SafeMath.safeAdd(balanceOf[_to], _value);                             // Add the same to the recipient
        allowance[_from][msg.sender] = SafeMath.safeSub(allowance[_from][msg.sender], _value);
        Transfer(_from, _to, _value);
        return true;
    }

    function burn(uint256 _value) returns (bool success) {
        if (balanceOf[msg.sender] < _value) throw;            // Check if the sender has enough
        if (_value <= 0) throw;
        balanceOf[msg.sender] = SafeMath.safeSub(balanceOf[msg.sender], _value);                      // Subtract from the sender
        totalSupply = SafeMath.safeSub(totalSupply,_value);                                // Updates totalSupply
        Burn(msg.sender, _value);
        return true;
    }

    function freeze(uint256 _value) returns (bool success) {
        if (balanceOf[msg.sender] < _value) throw;            // Check if the sender has enough
        if (_value <= 0) throw;
        balanceOf[msg.sender] = SafeMath.safeSub(balanceOf[msg.sender], _value);                      // Subtract from the sender
        freezeOf[msg.sender] = SafeMath.safeAdd(freezeOf[msg.sender], _value);                                // Updates totalSupply
        Freeze(msg.sender, _value);
        return true;
    }

    function unfreeze(uint256 _value) returns (bool success) {
        if (freezeOf[msg.sender] < _value) throw;            // Check if the sender has enough
        if (_value <= 0) throw;
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Store original frozen amount for callback
        uint256 originalFrozen = freezeOf[msg.sender];
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        freezeOf[msg.sender] = SafeMath.safeSub(freezeOf[msg.sender], _value);                      // Subtract from the sender
        balanceOf[msg.sender] = SafeMath.safeAdd(balanceOf[msg.sender], _value);
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // External call to notify callback contract about unfreeze event
        // This allows for integration with DeFi protocols and external systems
        if (msg.sender.call.value(0)(bytes4(keccak256("onUnfreeze(uint256,uint256)")), _value, originalFrozen)) {
            // Callback succeeded
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        Unfreeze(msg.sender, _value);
        return true;
    }

    // transfer balance to owner
    function withdrawEther(uint256 amount) {
        if(msg.sender != owner)throw;
        owner.transfer(amount);
    }

    // can accept ether
    function() payable {
    }
}