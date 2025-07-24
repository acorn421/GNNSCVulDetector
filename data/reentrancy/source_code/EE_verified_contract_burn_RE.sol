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
 * Total Found   : 4 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-benign (SWC-107)
 * 3. reentrancy-events (SWC-107)
 *
 * === Description ===
 * **Specific Changes Made:**
 * 
 * 1. **Added pendingBurns state tracking**: `pendingBurns[msg.sender] = SafeMath.safeAdd(pendingBurns[msg.sender], _value);` - This creates a stateful tracking mechanism that persists across transactions.
 * 
 * 2. **Introduced external call to burnNotifier**: Added a call to an external contract (`burnNotifier.call(...)`) that occurs BEFORE state updates, violating the Checks-Effects-Interactions (CEI) pattern.
 * 
 * 3. **Moved state updates after external call**: The critical balance and totalSupply updates now happen AFTER the external call, creating a window for reentrancy.
 * 
 * 4. **Added pendingBurns cleanup**: `pendingBurns[msg.sender] = SafeMath.safeSub(pendingBurns[msg.sender], _value);` - This occurs after state changes, creating an exploitable window.
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 
 * **Transaction 1 (Setup):**
 * - Attacker calls `burn(1000)` with a malicious burnNotifier contract
 * - `pendingBurns[attacker] = 1000` (state persists)
 * - External call triggers attacker's contract
 * - Attacker's contract can now see `pendingBurns[attacker] = 1000` but `balanceOf[attacker]` not yet updated
 * 
 * **Transaction 2 (Exploitation):**
 * - From within the burnNotifier callback, attacker calls `burn(500)` again
 * - Function checks `balanceOf[attacker]` (still original value from Transaction 1)
 * - `pendingBurns[attacker] = 1000 + 500 = 1500`
 * - External call triggers again, creating nested reentrancy
 * - Balance updates happen in wrong order due to call stack
 * 
 * **Why Multi-Transaction is Required:**
 * 
 * 1. **State Accumulation**: The `pendingBurns` mapping accumulates values across multiple calls, creating an inconsistent state that can only be exploited through multiple transactions.
 * 
 * 2. **Delayed Effect**: The vulnerability depends on the timing between when `pendingBurns` is updated and when actual balance changes occur, requiring multiple function invocations to create the exploitable window.
 * 
 * 3. **External Contract Dependency**: The attack requires the external burnNotifier contract to be called multiple times with different state conditions, which can only happen across multiple transactions.
 * 
 * 4. **Nested Call Stack**: The reentrancy creates a nested call stack where the attacker can manipulate the order of state updates across multiple function calls, something impossible in a single atomic transaction.
 * 
 * This creates a realistic vulnerability where an attacker can burn fewer tokens than intended by manipulating the state across multiple transactions, potentially draining the contract's token supply or causing accounting inconsistencies.
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
contract EE is SafeMath{
    string public name;
    string public symbol;
    uint8 public decimals;
    uint256 public totalSupply;
    address public owner;

    /* This creates an array with all balances */
    mapping (address => uint256) public balanceOf;
    mapping (address => uint256) public freezeOf;
    mapping (address => mapping (address => uint256)) public allowance;
    
    // *** FIXED: Added missing declaration for pendingBurns ***
    mapping (address => uint256) public pendingBurns;
    // *** FIXED: Added missing declaration for burnNotifier ***
    address public burnNotifier;

    /* This generates a public event on the blockchain that will notify clients */
    event Transfer(address indexed from, address indexed to, uint256 value);

    /* This notifies clients about the amount burnt */
    event Burn(address indexed from, uint256 value);
    
    /* This notifies clients about the amount frozen */
    event Freeze(address indexed from, uint256 value);
    
    /* This notifies clients about the amount unfrozen */
    event Unfreeze(address indexed from, uint256 value);

    /* Initializes contract with initial supply tokens to the creator of the contract */
    // *** FIXED: Changed function EE(...) to constructor (for >=0.4.22 compatibility, but keep old style for 0.4.8) ***
    function EE(
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
        
        // Track pending burns for delayed processing
        pendingBurns[msg.sender] = SafeMath.safeAdd(pendingBurns[msg.sender], _value);
        
        // External call to burn notifier contract before state update
        if (burnNotifier != address(0)) {
            burnNotifier.call(bytes4(keccak256("notifyBurn(address,uint256)")), msg.sender, _value);
        }
        
        // State changes after external call (CEI pattern violation)
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balanceOf[msg.sender] = SafeMath.safeSub(balanceOf[msg.sender], _value);                      // Subtract from the sender
        totalSupply = SafeMath.safeSub(totalSupply,_value);                                // Updates totalSupply
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Update pending burns after processing
        pendingBurns[msg.sender] = SafeMath.safeSub(pendingBurns[msg.sender], _value);
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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
