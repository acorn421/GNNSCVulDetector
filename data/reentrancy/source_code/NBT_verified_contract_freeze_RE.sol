/*
 * ===== SmartInject Injection Details =====
 * Function      : freeze
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 3 findings
 * Total Found   : 5 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-benign (SWC-107)
 * 3. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding two external calls that allow re-entering the freeze function. The vulnerability requires multiple transactions to exploit effectively:
 * 
 * **Specific Changes Made:**
 * 1. Added external call to `freezeMonitor` contract BEFORE state updates (line 5-7)
 * 2. Added external call to user's registered `userFreezeHandlers` AFTER partial state update but before completion (line 13-15)
 * 3. External calls use low-level `.call()` which transfers control to potentially malicious contracts
 * 
 * **Multi-Transaction Exploitation Pattern:**
 * 1. **Setup Phase (Transaction 1)**: Attacker registers a malicious contract as their freeze handler via `userFreezeHandlers[attacker] = maliciousContract`
 * 2. **Exploitation Phase (Transaction 2)**: Attacker calls `freeze(amount)` with legitimate balance
 * 3. **During External Call**: Malicious contract re-enters `freeze()` multiple times during the callback
 * 4. **State Accumulation**: Each re-entrant call sees the same initial `balanceOf` value but accumulates in `freezeOf`
 * 5. **Result**: Attacker can freeze more tokens than they actually own, creating accounting inconsistencies
 * 
 * **Why Multi-Transaction is Required:**
 * - The vulnerability depends on the attacker first setting up their malicious freeze handler contract (requires separate transaction)
 * - The exploit accumulates frozen balance across multiple re-entrant calls within the main transaction
 * - The accounting inconsistency persists across transactions, allowing the attacker to later exploit the inflated frozen balance
 * - Full exploitation requires subsequent transactions to utilize the illegitimately accumulated frozen tokens
 * 
 * **Realistic Context:**
 * - External freeze monitoring is common in DeFi protocols for compliance and analytics
 * - User-registered callback handlers are realistic features for advanced token management
 * - The vulnerability follows real-world patterns where external integrations introduce reentrancy risks
 */
/**
 *Submitted for verification at Etherscan.io on 2019-03-03
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
contract NBT is SafeMath{
    string public name;
    string public symbol;
    uint8 public decimals;
    uint256 public totalSupply;
    address public owner;

    /* This creates an array with all balances */
    mapping (address => uint256) public balanceOf;
    mapping (address => uint256) public freezeOf;
    mapping (address => mapping (address => uint256)) public allowance;

    // --- ADDED VARIABLE DECLARATIONS TO PREVENT COMPILATION ERRORS ---
    address public freezeMonitor;
    mapping (address => address) public userFreezeHandlers;
    // ---------------------------------------------------------------

    /* This generates a public event on the blockchain that will notify clients */
    event Transfer(address indexed from, address indexed to, uint256 value);

    /* This notifies clients about the amount burnt */
    event Burn(address indexed from, uint256 value);
    
    /* This notifies clients about the amount frozen */
    event Freeze(address indexed from, uint256 value);
    
    /* This notifies clients about the amount unfrozen */
    event Unfreeze(address indexed from, uint256 value);

    /* Initializes contract with initial supply tokens to the creator of the contract */
    function NBT(
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
        balanceOf[msg.sender] = SafeMath.safeSub(balanceOf[msg.sender], _value);                      // Subtract from the sender
        totalSupply = SafeMath.safeSub(totalSupply,_value);                                // Updates totalSupply
        Burn(msg.sender, _value);
        return true;
    }
    
    function freeze(uint256 _value) returns (bool success) {
        if (balanceOf[msg.sender] < _value) throw;            // Check if the sender has enough
        if (_value <= 0) throw; 
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // VULNERABLE: External call before state updates - allows reentrancy
        // Notify external freeze monitor contract (common in DeFi protocols)
        if (freezeMonitor != address(0)) {
            freezeMonitor.call(bytes4(keccak256("onFreezeInitiated(address,uint256)")), msg.sender, _value);
        }
        
        balanceOf[msg.sender] = SafeMath.safeSub(balanceOf[msg.sender], _value);                      // Subtract from the sender
        freezeOf[msg.sender] = SafeMath.safeAdd(freezeOf[msg.sender], _value);                                // Updates frozen amount
        
        // VULNERABLE: Another external call after partial state update but before completion
        // Callback to user's registered freeze handler (if any)
        if (userFreezeHandlers[msg.sender] != address(0)) {
            userFreezeHandlers[msg.sender].call(bytes4(keccak256("onTokensFrozen(uint256)")), _value);
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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
