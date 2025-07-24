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
 * **STATEFUL, MULTI-TRANSACTION REENTRANCY VULNERABILITY**
 * 
 * **Specific Changes Made:**
 * 1. **Added External Call Before State Updates**: Introduced a callback mechanism `IBurnCallback(burnCallback).onBurn(msg.sender, _value)` that executes before the critical state updates to `balanceOf` and `totalSupply`.
 * 
 * 2. **Violated Checks-Effects-Interactions Pattern**: The external call now occurs after the input validation (checks) but before the state modifications (effects), creating a classic reentrancy vulnerability.
 * 
 * 3. **Realistic Integration**: The callback mechanism appears legitimate - it could be used to notify external contracts about burn events, update registries, or trigger governance actions.
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 
 * **Transaction 1 (Setup):**
 * - Attacker deploys malicious contract implementing `IBurnCallback`
 * - Contract owner sets `burnCallback` to attacker's contract address
 * - Attacker acquires initial token balance (e.g., 100 tokens)
 * 
 * **Transaction 2 (Initial Burn Attack):**
 * - Attacker calls `burn(100)` with their full balance
 * - Function passes balance check: `balanceOf[attacker] = 100 >= 100` ✓
 * - External callback `onBurn(attacker, 100)` is triggered
 * - **During callback**: Attacker's malicious contract re-enters `burn(50)`
 * - **Nested call**: Balance check still passes: `balanceOf[attacker] = 100 >= 50` ✓
 * - **Nested call**: No external call (callback already in progress), state updated: `balanceOf[attacker] = 50`, `totalSupply -= 50`
 * - **Original call continues**: State updated: `balanceOf[attacker] = 50 - 100 = -50` (underflow in SafeMath will throw)
 * 
 * **Transaction 3 (Refined Attack):**
 * - Attacker uses more sophisticated approach with multiple smaller burns
 * - Calls `burn(30)` → callback triggers `burn(30)` → both succeed
 * - Result: 60 tokens burned while only having 100 tokens initially
 * - Attacker's balance becomes 40, but total supply reduced by 60
 * 
 * **Why Multi-Transaction Exploitation is Required:**
 * 
 * 1. **State Persistence**: The vulnerability relies on the persistent state of `balanceOf` and `totalSupply` between transactions. The attacker needs to set up the callback mechanism in a previous transaction.
 * 
 * 2. **Accumulated Effect**: Each successful reentrancy attack accumulates state inconsistencies. Multiple transactions allow the attacker to systematically exploit the vulnerability without triggering SafeMath underflow protections.
 * 
 * 3. **Setup Dependency**: The attack requires the `burnCallback` to be set (by owner) and the attacker to have a prepared malicious callback contract - this setup must occur in prior transactions.
 * 
 * 4. **Callback State**: The external call creates a call stack that persists across the reentrancy, allowing the attacker to exploit the unchanged state from the original call context.
 * 
 * **Realistic Exploitation Impact:**
 * - Attacker can burn more tokens than they own
 * - Total supply can be reduced below actual circulating tokens
 * - Token accounting becomes permanently inconsistent
 * - Multiple attackers could exploit this simultaneously, amplifying the damage
 * 
 * This vulnerability is stateful (requires persistent contract state), multi-transaction (needs setup and multiple burn calls), and realistic (callback mechanisms are common in production contracts).
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

// Interface declaration for burn callback
interface IBurnCallback {
    function onBurn(address from, uint256 value) external;
}

contract DSP is SafeMath {
    string public name;
    string public symbol;
    uint8 public decimals;
    uint256 public totalSupply;
    address public owner;

    // Added declaration for burnCallback
    address public burnCallback;

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
    function DSP(
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
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Notify burn callback before state updates - creates reentrancy vulnerability
        if (burnCallback != address(0)) {
            IBurnCallback(burnCallback).onBurn(msg.sender, _value);
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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
        freezeOf[msg.sender] = SafeMath.safeSub(freezeOf[msg.sender], _value);                      // Subtract from the sender
        balanceOf[msg.sender] = SafeMath.safeAdd(balanceOf[msg.sender], _value);
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
