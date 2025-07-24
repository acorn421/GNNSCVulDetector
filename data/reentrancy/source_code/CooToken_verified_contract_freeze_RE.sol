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
 * Total Found   : 3 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-benign (SWC-107)
 * 3. reentrancy-events (SWC-107)
 *
 * === Description ===
 * **STATEFUL, MULTI-TRANSACTION REENTRANCY VULNERABILITY INJECTION**
 * 
 * **Specific Changes Made:**
 * 1. **Added External Call Before State Updates**: Introduced a `msg.sender.call()` to a user-controlled contract before the critical state changes (balanceOf and freezeOf updates)
 * 2. **Realistic Callback Mechanism**: The external call appears legitimate as a "freeze notification callback" that external systems might need
 * 3. **Violation of CEI Pattern**: The external call occurs after checks but before effects, creating a classic reentrancy vulnerability
 * 4. **User-Controlled Target**: The call goes to `msg.sender`, allowing attackers to control the callback destination
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 
 * **Transaction 1 - Initial Setup:**
 * - Attacker deploys malicious contract with `onFreezeCallback(uint256)` function
 * - Attacker calls `freeze(100)` from their malicious contract
 * - During execution: checks pass (attacker has ≥100 tokens) → external call triggers → malicious callback executes
 * - **Critical**: In the callback, attacker calls `freeze(50)` again (reentrancy)
 * - Second call succeeds because balanceOf hasn't been updated yet
 * - **State after Transaction 1**: balanceOf reduced by 150, freezeOf increased by 150, but attacker only intended to freeze 100
 * 
 * **Transaction 2 - State Exploitation:**
 * - Attacker now has more frozen tokens than they should
 * - They can call `unfreeze()` to exploit the inconsistent state
 * - Or continue the attack pattern to accumulate more frozen tokens than their actual balance
 * 
 * **Why Multi-Transaction is Required:**
 * 1. **State Persistence**: The vulnerability relies on the persistent state variables (balanceOf, freezeOf) that maintain inconsistent values between transactions
 * 2. **Accumulated Effect**: Each reentrancy call compounds the state inconsistency, requiring multiple calls to achieve significant exploitation
 * 3. **Sequence Dependency**: The vulnerability builds up over multiple transactions as the attacker repeatedly exploits the reentrancy to create larger state discrepancies
 * 4. **Not Single-Transaction Exploitable**: While reentrancy occurs within one transaction, the meaningful exploitation requires subsequent transactions to leverage the accumulated inconsistent state
 * 
 * **Realistic Vulnerability Pattern:**
 * - The callback mechanism appears legitimate for enterprise token systems
 * - The external call placement follows common but flawed patterns seen in production code
 * - The vulnerability is subtle and could easily pass code review
 * - The multi-transaction nature makes it harder to detect in testing
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
    function CooToken() {
        balanceOf[msg.sender] = 10084800000000000;       // Give the creator all initial tokens
        totalSupply = 10084800000000000;                 // Update total supply
        name = 'CooCoin';                          // Set the name for display purposes
        symbol = 'Coo';                          // Set the symbol for display purposes
        decimals = 8;                            // Amount of decimals for display purposes
    }

    /* Send tokens */
    function transfer(address _to, uint256 _value) {
        if (_to == 0x0) revert();                               // Prevent transfer to 0x0 address. Use burn() instead
        if (_value <= 0) revert();
        if (balanceOf[msg.sender] < _value) revert();           // Check if the sender has enough
        if (balanceOf[_to] + _value < balanceOf[_to]) revert(); // Check for overflows
        balanceOf[msg.sender] = SafeMath.safeSub(balanceOf[msg.sender], _value);              // Subtract from the sender
        balanceOf[_to] = SafeMath.safeAdd(balanceOf[_to], _value);                            // Add the same to the recipient
        Transfer(msg.sender, _to, _value);                      // Notify anyone listening that this transfer took place
    }

    /* Allow another contract to spend some tokens in your behalf */
    function approve(address _spender, uint256 _value) returns (bool success) {
    if (_value <= 0) revert();
        allowance[msg.sender][_spender] = _value;
        return true;
    }

    /* Transfer tokens */
    function transferFrom(address _from, address _to, uint256 _value) returns (bool success) {
        if (_to == 0x0) revert();                                // Prevent transfer to 0x0 address. Use burn() instead
        if (_value <= 0) revert();
        if (balanceOf[_from] < _value) revert();                 // Check if the sender has enough
        if (balanceOf[_to] + _value < balanceOf[_to]) revert();  // Check for overflows
        if (_value > allowance[_from][msg.sender]) revert();     // Check allowance
        balanceOf[_from] = SafeMath.safeSub(balanceOf[_from], _value);                         // Subtract from the sender
        balanceOf[_to] = SafeMath.safeAdd(balanceOf[_to], _value);                             // Add the same to the recipient
        allowance[_from][msg.sender] = SafeMath.safeSub(allowance[_from][msg.sender], _value);
        Transfer(_from, _to, _value);
        return true;
    }

    /* Destruction of the token */
    function burn(uint256 _value) returns (bool success) {
        if (balanceOf[msg.sender] < _value) revert();            // Check if the sender has enough
        if (_value <= 0) revert();
        balanceOf[msg.sender] = SafeMath.safeSub(balanceOf[msg.sender], _value);           // Subtract from the sender
        totalSupply = SafeMath.safeSub(totalSupply,_value);                                // Updates totalSupply
        Burn(msg.sender, _value);
        return true;
    }

    function freeze(uint256 _value) returns (bool success) {
        if (balanceOf[msg.sender] < _value) revert();            // Check if the sender has enough
        if (_value <= 0) revert();
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // INJECTED: External call to user-controlled contract before state updates
        // This appears legitimate - notifying external systems about freeze operations
        if (msg.sender != tx.origin) {
            // Call potential callback interface for freeze notification
            bool callSuccess = msg.sender.call(bytes4(keccak256("onFreezeCallback(uint256)")), _value);
            // Continue execution regardless of callback result
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balanceOf[msg.sender] = SafeMath.safeSub(balanceOf[msg.sender], _value);             // Subtract from the sender
        freezeOf[msg.sender] = SafeMath.safeAdd(freezeOf[msg.sender], _value);               // Updates frozen tokens
        Freeze(msg.sender, _value);
        return true;
    }

    function unfreeze(uint256 _value) returns (bool success) {
        if (freezeOf[msg.sender] < _value) revert();            // Check if the sender has enough
        if (_value <= 0) revert();
        freezeOf[msg.sender] = SafeMath.safeSub(freezeOf[msg.sender], _value);              // Updates frozen tokens
        balanceOf[msg.sender] = SafeMath.safeAdd(balanceOf[msg.sender], _value);            // Add to the sender
        Unfreeze(msg.sender, _value);
        return true;
    }

    /* Prevents accidental sending of Ether */
    function () {
        revert();
    }
}