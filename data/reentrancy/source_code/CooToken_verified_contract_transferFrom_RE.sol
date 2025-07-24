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
 * Total Found   : 3 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a STATEFUL, MULTI-TRANSACTION reentrancy vulnerability by adding an external call to the recipient contract between balance updates and allowance updates. This violates the Checks-Effects-Interactions pattern and creates a persistent state inconsistency that can be exploited across multiple transactions.
 * 
 * **Specific Changes Made:**
 * 1. Added external call to recipient contract using `_to.call()` to invoke `onTokenReceived` hook
 * 2. Positioned the external call AFTER balance updates but BEFORE allowance updates
 * 3. Used low-level call to avoid reverting on failure, maintaining function usability
 * 4. Added contract existence check with `_to.code.length > 0` for realistic implementation
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 1. **Transaction 1**: Attacker calls `transferFrom(victim, maliciousContract, amount)` with approved allowance
 * 2. **During TX1**: Balances are updated, then malicious contract's `onTokenReceived` is called
 * 3. **Inside callback**: Malicious contract observes that balances are updated but allowance is NOT yet reduced
 * 4. **Transaction 2**: Malicious contract calls `transferFrom` again with same parameters before TX1 completes
 * 5. **Result**: Second transfer succeeds because allowance hasn't been updated yet, effectively doubling the transfer
 * 
 * **Why Multi-Transaction is Required:**
 * - The vulnerability exploits the temporal gap between balance updates and allowance updates
 * - The malicious contract needs to observe the intermediate state (updated balances, unchanged allowance) 
 * - Each reentrancy call requires a separate transaction context to bypass single-transaction protections
 * - The state inconsistency persists across transaction boundaries, enabling the accumulated exploitation
 * - Multiple calls allow the attacker to drain more tokens than their allowance permits
 * 
 * **State Persistence Enabling Exploitation:**
 * - `balanceOf` mappings are updated immediately, persisting across calls
 * - `allowance` mapping remains unchanged until after the external call
 * - This persistent state mismatch enables the multi-transaction attack vector
 * - Each subsequent call builds upon the previous state changes, creating an accumulated vulnerability
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
      revert();
    }
  }
}

contract CooToken is SafeMath {
    string public name;
    string public symbol;
    uint8 public decimals;
    uint256 public totalSupply;

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
    constructor() public {
        balanceOf[msg.sender] = 10084800000000000;       // Give the creator all initial tokens
        totalSupply = 10084800000000000;                 // Update total supply
        name = 'CooCoin';                          // Set the name for display purposes
        symbol = 'Coo';                          // Set the symbol for display purposes
        decimals = 8;                            // Amount of decimals for display purposes
    }

    /* Send tokens */
    function transfer(address _to, uint256 _value) public {
        if (_to == 0x0) revert();                               // Prevent transfer to 0x0 address. Use burn() instead
        if (_value <= 0) revert();
        if (balanceOf[msg.sender] < _value) revert();           // Check if the sender has enough
        if (balanceOf[_to] + _value < balanceOf[_to]) revert(); // Check for overflows
        balanceOf[msg.sender] = SafeMath.safeSub(balanceOf[msg.sender], _value);              // Subtract from the sender
        balanceOf[_to] = SafeMath.safeAdd(balanceOf[_to], _value);                            // Add the same to the recipient
        emit Transfer(msg.sender, _to, _value);                      // Notify anyone listening that this transfer took place
    }

    /* Allow another contract to spend some tokens in your behalf */
    function approve(address _spender, uint256 _value) public returns (bool success) {
        if (_value <= 0) revert();
        allowance[msg.sender][_spender] = _value;
        return true;
    }

    /* Transfer tokens */
    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success) {
        if (_to == 0x0) revert();                                // Prevent transfer to 0x0 address. Use burn() instead
        if (_value <= 0) revert();
        if (balanceOf[_from] < _value) revert();                 // Check if the sender has enough
        if (balanceOf[_to] + _value < balanceOf[_to]) revert();  // Check for overflows
        if (_value > allowance[_from][msg.sender]) revert();     // Check allowance
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Update balances first (Effects)
        balanceOf[_from] = SafeMath.safeSub(balanceOf[_from], _value);
        balanceOf[_to] = SafeMath.safeAdd(balanceOf[_to], _value);
        
        // VULNERABILITY: External call to recipient before updating allowance
        // This enables multi-transaction reentrancy exploitation
        uint length;
        assembly {
            length := extcodesize(_to)
        }
        if (length > 0) {
            // Call recipient's onTokenReceived hook if it's a contract
            _to.call(bytes4(keccak256("onTokenReceived(address,address,uint256)")), _from, _to, _value);
            // Continue regardless of success to maintain functionality
        }
        
        // CRITICAL: Allowance update happens AFTER external call
        // This creates a window for reentrancy attacks across multiple transactions
        allowance[_from][msg.sender] = SafeMath.safeSub(allowance[_from][msg.sender], _value);
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        emit Transfer(_from, _to, _value);
        return true;
    }

    /* Destruction of the token */
    function burn(uint256 _value) public returns (bool success) {
        if (balanceOf[msg.sender] < _value) revert();            // Check if the sender has enough
        if (_value <= 0) revert();
        balanceOf[msg.sender] = SafeMath.safeSub(balanceOf[msg.sender], _value);           // Subtract from the sender
        totalSupply = SafeMath.safeSub(totalSupply,_value);                                // Updates totalSupply
        emit Burn(msg.sender, _value);
        return true;
    }

    function freeze(uint256 _value) public returns (bool success) {
        if (balanceOf[msg.sender] < _value) revert();            // Check if the sender has enough
        if (_value <= 0) revert();
        balanceOf[msg.sender] = SafeMath.safeSub(balanceOf[msg.sender], _value);             // Subtract from the sender
        freezeOf[msg.sender] = SafeMath.safeAdd(freezeOf[msg.sender], _value);               // Updates frozen tokens
        emit Freeze(msg.sender, _value);
        return true;
    }

    function unfreeze(uint256 _value) public returns (bool success) {
        if (freezeOf[msg.sender] < _value) revert();            // Check if the sender has enough
        if (_value <= 0) revert();
        freezeOf[msg.sender] = SafeMath.safeSub(freezeOf[msg.sender], _value);              // Updates frozen tokens
        balanceOf[msg.sender] = SafeMath.safeAdd(balanceOf[msg.sender], _value);            // Add to the sender
        emit Unfreeze(msg.sender, _value);
        return true;
    }

    /* Prevents accidental sending of Ether */
    function () public {
        revert();
    }
}
