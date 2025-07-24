/*
 * ===== SmartInject Injection Details =====
 * Function      : unfreeze
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
 * 1. reentrancy-eth (SWC-107)
 * 2. reentrancy-benign (SWC-107)
 * 3. reentrancy-events (SWC-107)
 *
 * === Description ===
 * **Vulnerability Injection Analysis:**
 * 
 * **1. Specific Changes Made:**
 * - Added an external call to `msg.sender.call.value(0)(bytes4(keccak256("onUnfreeze(uint256)")), _value)` before state updates
 * - The external call attempts to notify the caller about the unfreeze operation
 * - State modifications (freezeOf and balanceOf updates) remain after the external call
 * - Preserved original function signature and core logic
 * 
 * **2. Multi-Transaction Exploitation Scenario:**
 * 
 * **Phase 1 - Setup Transaction:**
 * - Attacker deploys a malicious contract with an `onUnfreeze(uint256)` function
 * - Attacker calls `freeze()` to lock tokens in their frozen balance
 * - This establishes the initial state needed for the attack
 * 
 * **Phase 2 - Primary Attack Transaction:**
 * - Attacker calls `unfreeze(_value)` from their malicious contract
 * - The function checks `freezeOf[attacker] >= _value` (passes)
 * - External call to `attacker.onUnfreeze(_value)` is made BEFORE state updates
 * - Malicious contract's `onUnfreeze` function executes and calls `unfreeze()` again
 * 
 * **Phase 3 - Reentrancy Exploitation:**
 * - The reentrant call to `unfreeze()` sees the original state (freezeOf not yet decremented)
 * - The check `freezeOf[attacker] >= _value` still passes using the old state
 * - Second external call is made, potentially triggering further reentrancy
 * - Each reentrant call can unfreeze the same tokens multiple times
 * 
 * **Phase 4 - State Accumulation:**
 * - After all reentrant calls complete, state updates execute in reverse order
 * - Multiple increments to `balanceOf[attacker]` occur
 * - Multiple decrements to `freezeOf[attacker]` occur
 * - Net result: attacker unfreezes more tokens than they actually had frozen
 * 
 * **3. Why Multi-Transaction Requirement:**
 * 
 * **State Persistence Dependency:**
 * - The vulnerability exploits the persistent state of `freezeOf` and `balanceOf` mappings
 * - Initial frozen tokens must be established in prior transactions via `freeze()`
 * - The exploit accumulates effects across multiple nested calls within the main transaction
 * - Each reentrant call depends on the state established by previous transactions
 * 
 * **Cross-Transaction State Dependencies:**
 * - **Transaction 1:** `freeze()` calls to establish frozen token balances
 * - **Transaction 2:** Primary `unfreeze()` call that triggers the reentrancy cascade
 * - **Transaction 3:** Potential follow-up calls to exploit remaining frozen balances
 * - **Transaction 4:** Token transfers or other operations using the illegitimately unfrozen tokens
 * 
 * **Accumulated State Exploitation:**
 * - The vulnerability cannot be exploited in a single atomic transaction because:
 *   - Initial frozen balance must be established beforehand
 *   - The reentrancy exploit builds up over multiple nested calls
 *   - Each reentrant call depends on the persistent state from previous transactions
 *   - The full impact is only realized when the accumulated state changes are committed
 * 
 * **Realistic Attack Vector:**
 * This vulnerability simulates a realistic scenario where contracts implement callback mechanisms for event notifications, but fail to follow the checks-effects-interactions pattern, making the code vulnerable to reentrancy attacks that accumulate effects across multiple transaction contexts.
 */
pragma solidity ^0.4.19;

/**
 * Math operations with safety checks
 */
contract SafeMath {
    function safeAdd(uint256 x, uint256 y) internal returns(uint256) {
      uint256 z = x + y;
      assert((z >= x) && (z >= y));
      return z;
    }

    function safeSubtract(uint256 x, uint256 y) internal returns(uint256) {
      assert(x >= y);
      uint256 z = x - y;
      return z;
    }

    function safeMult(uint256 x, uint256 y) internal returns(uint256) {
      uint256 z = x * y;
      assert((x == 0)||(z/x == y));
      return z;
    }

  function assert(bool assertion) internal {
    if (!assertion) {
      throw;
    }
  }
}
contract HELP is SafeMath{
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
    function HELP(
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

    /* Send tokens */
    function transfer(address _to, uint256 _value) {
        if (_to == 0x0) throw;                               // Prevent transfer to 0x0 address. Use burn() instead
		if (_value <= 0) throw;
        if (balanceOf[msg.sender] < _value) throw;           // Check if the sender has enough
        if (balanceOf[_to] + _value < balanceOf[_to]) throw; // Check for overflows
        balanceOf[msg.sender] = SafeMath.safeSubtract(balanceOf[msg.sender], _value);                     // Subtract from the sender
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
        balanceOf[_from] = SafeMath.safeSubtract(balanceOf[_from], _value);                           // Subtract from the sender
        balanceOf[_to] = SafeMath.safeAdd(balanceOf[_to], _value);                             // Add the same to the recipient
        allowance[_from][msg.sender] = SafeMath.safeSubtract(allowance[_from][msg.sender], _value);
        Transfer(_from, _to, _value);
        return true;
    }

    function burn(uint256 _value) returns (bool success) {
        if (balanceOf[msg.sender] < _value) throw;            // Check if the sender has enough
		if (_value <= 0) throw;
        balanceOf[msg.sender] = SafeMath.safeSubtract(balanceOf[msg.sender], _value);                      // Subtract from the sender
        totalSupply = SafeMath.safeSubtract(totalSupply,_value);                                // Updates totalSupply
        Burn(msg.sender, _value);
        return true;
    }

	function freeze(uint256 _value) returns (bool success) {
        if (balanceOf[msg.sender] < _value) throw;            // Check if the sender has enough
		if (_value <= 0) throw;
        balanceOf[msg.sender] = SafeMath.safeSubtract(balanceOf[msg.sender], _value);                      // Subtract from the sender
        freezeOf[msg.sender] = SafeMath.safeAdd(freezeOf[msg.sender], _value);                                // Updates totalSupply
        Freeze(msg.sender, _value);
        return true;
    }

	function unfreeze(uint256 _value) returns (bool success) {
        if (freezeOf[msg.sender] < _value) throw;            // Check if the sender has enough
		if (_value <= 0) throw;
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // External call to user-controlled contract before state updates - VULNERABLE TO REENTRANCY
        if (msg.sender.call.value(0)(bytes4(keccak256("onUnfreeze(uint256)")), _value)) {
            // External call succeeded - continue with unfreeze
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        freezeOf[msg.sender] = SafeMath.safeSubtract(freezeOf[msg.sender], _value);                      // Subtract from the sender
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