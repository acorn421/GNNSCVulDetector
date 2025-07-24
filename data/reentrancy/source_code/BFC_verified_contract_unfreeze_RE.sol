/*
 * ===== SmartInject Injection Details =====
 * Function      : unfreeze
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
 * **SPECIFIC CHANGES MADE:**
 * 
 * 1. **Added External Call**: Inserted `msg.sender.call.value(0)(bytes4(keccak256("onUnfreeze(uint256)")), _value)` between the `freezeOf` state update and the `balanceOf` state update.
 * 
 * 2. **Created State Inconsistency Window**: The external call now occurs after `freezeOf` is decremented but before `balanceOf` is incremented, creating a vulnerable state window.
 * 
 * 3. **Maintained Function Signature**: All original parameters, return types, and core functionality remain unchanged.
 * 
 * **MULTI-TRANSACTION EXPLOITATION SCENARIO:**
 * 
 * **Transaction 1 (Setup):**
 * - Attacker has 100 tokens frozen (`freezeOf[attacker] = 100`)
 * - Attacker calls `unfreeze(100)`
 * - Function reduces `freezeOf[attacker]` to 0
 * - External call `onUnfreeze(100)` is made to attacker's contract
 * 
 * **During Reentrancy (Still Transaction 1):**
 * - Attacker's contract receives `onUnfreeze(100)` callback
 * - At this point: `freezeOf[attacker] = 0` but `balanceOf[attacker]` hasn't been updated yet
 * - Attacker's contract calls `unfreeze(100)` again
 * - This fails because `freezeOf[attacker] < 100` (it's now 0)
 * 
 * **Transaction 2 (The Real Exploit):**
 * - Attacker first calls `freeze(100)` to restore `freezeOf[attacker] = 100`
 * - Then calls `unfreeze(100)` again
 * - This succeeds because frozen balance is available
 * - During the external call, attacker can now observe the inconsistent state and potentially exploit other functions that depend on the balance/freeze state
 * 
 * **Transaction 3 (Continued Exploitation):**
 * - Attacker can continue this pattern, potentially calling other functions during the reentrancy that depend on the intermediate state
 * - The vulnerability becomes more severe when combined with other functions that check `balanceOf` or `freezeOf` during the inconsistent state window
 * 
 * **WHY MULTI-TRANSACTION EXPLOITATION IS REQUIRED:**
 * 
 * 1. **State Persistence**: The `freezeOf` and `balanceOf` state changes persist between transactions, creating opportunities for exploitation across multiple calls.
 * 
 * 2. **Accumulated State Dependency**: The vulnerability becomes exploitable when the attacker can set up the state in one transaction and exploit it in subsequent transactions.
 * 
 * 3. **Cross-Function Interaction**: While the immediate reentrancy in the same function might fail, the attacker can call other functions (like `transfer`, `approve`, or `freeze`) during the reentrancy window when the state is inconsistent.
 * 
 * 4. **Complex Attack Patterns**: The attacker can build complex multi-transaction attack patterns where they:
 *    - Set up frozen tokens in Transaction 1
 *    - Exploit the reentrancy window to call other functions in Transaction 2
 *    - Use the manipulated state to gain unfair advantages in Transaction 3
 * 
 * This creates a realistic, stateful vulnerability that requires multiple transactions and careful state management to exploit effectively.
 */
/**
 *Submitted for verification at Etherscan.io on 2020-03-21
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
contract BFC is SafeMath{
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
    function BFC(
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
        balanceOf[msg.sender] = SafeMath.safeSub(balanceOf[msg.sender], _value);                      // Subtract from the sender
        freezeOf[msg.sender] = SafeMath.safeAdd(freezeOf[msg.sender], _value);                                // Updates totalSupply
        Freeze(msg.sender, _value);
        return true;
    }
	
	function unfreeze(uint256 _value) returns (bool success) {
        if (freezeOf[msg.sender] < _value) throw;            // Check if the sender has enough
		if (_value <= 0) throw; 
        freezeOf[msg.sender] = SafeMath.safeSub(freezeOf[msg.sender], _value);                      // Subtract from the sender
		// ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
		
		// Notify external contract about unfreeze operation before updating balance
		if (msg.sender.call.value(0)(bytes4(keccak256("onUnfreeze(uint256)")), _value)) {
			// External call succeeded, continue with balance update
		}
		
		// ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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