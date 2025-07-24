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
 * Total Found   : 3 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-benign (SWC-107)
 * 2. reentrancy-events (SWC-107)
 *
 * === Description ===
 * **Vulnerability Injection Details:**
 * 
 * **1. Specific Changes Made:**
 * - Added external call `msg.sender.call.value(0)(abi.encodeWithSignature("onUnfreeze(uint256,uint256)", _value, originalFrozen))` between freezeOf update and balanceOf update
 * - Introduced intermediate state where freezeOf is updated but balanceOf is not yet updated
 * - Added originalFrozen variable to track the state before modification
 * 
 * **2. Multi-Transaction Exploitation Scenario:**
 * Transaction 1: Attacker calls unfreeze(100) with 100 frozen tokens
 * - freezeOf[attacker] reduced from 100 to 0
 * - External call triggers attacker's onUnfreeze callback
 * - In callback, attacker calls unfreeze(50) again (reentrancy)
 * - Second call sees freezeOf[attacker] = 0, so check fails safely
 * - But attacker can call freeze(50) first to manipulate state
 * 
 * Transaction 2: Attacker calls freeze(50) to set up state
 * Transaction 3: Attacker calls unfreeze(100) 
 * - freezeOf[attacker] = 50, but check passes for 100 due to state manipulation
 * - External call made with inconsistent state
 * - Attacker can exploit the gap between freezeOf and balanceOf updates
 * 
 * **3. Why Multi-Transaction is Required:**
 * - Single transaction reentrancy is limited by the freezeOf check
 * - Attacker needs to first manipulate freezeOf state through separate freeze() calls
 * - The vulnerability exploits the persistent state between transactions where freezeOf and balanceOf can be inconsistent
 * - Multiple transactions allow the attacker to accumulate state inconsistencies and exploit them when external calls are made
 * - The attack requires building up frozen balance in one transaction, then exploiting the external call window in another transaction to create impossible state combinations
 * 
 * **4. Stateful Nature:**
 * - The vulnerability depends on the persistent state of freezeOf and balanceOf mappings
 * - State changes from previous transactions (freeze/unfreeze calls) affect the exploitability
 * - The external call window creates opportunities for state manipulation that persist across transaction boundaries
 * - Attackers can build up complex state scenarios over multiple transactions before triggering the final exploit
 */
pragma solidity ^0.4.8;

/* Math operations with safety checks */
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

/* SGCC ERC20 Token */
contract SGCC is SafeMath { 
	string public name;
	string public symbol;
	uint8 public decimals;
	uint256 public totalSupply;
	address public owner;
	
	/* This creates an array with all balances */
	mapping (address => uint256) public balanceOf;
	mapping (address => uint256) public freezeOf;
	mapping (address => mapping (address => uint256)) public allowance;
	
	/* This generates a public event for notifying clients of transfers */ 
	event Transfer(address indexed from, address indexed to, uint256 value);
	/* This notifies clients about the amount burnt */ 
	event Burn(address indexed from, uint256 value);
	/* This notifies clients about the amount frozen */ 
	event Freeze(address indexed from, uint256 value);
	/* This notifies clients about the amount unfrozen */ 
	event Unfreeze(address indexed from, uint256 value);

	/* Initializes contract with initial supply of tokens to the creator of the contract */ 
	function SGCC() public {
		decimals = 18;
		balanceOf[msg.sender] = 20000000000 * (10 ** uint256(decimals)); // Give the creator all initial tokens
		totalSupply = 20000000000 * (10 ** uint256(decimals)); // Update total supply
		name = 'SGCC'; // Set the name for display purposes
		symbol = 'SGCC'; // Set the symbol for display purposes
		owner = msg.sender;
	}

	/* Send coins from the caller's account */
	function transfer(address _to, uint256 _value) public {
		if (_to == 0x0) throw; // Prevent transfer to 0x0 address. Use burn() instead 
		if (_value <= 0) throw;
		if (balanceOf[msg.sender] < _value) throw; // Check if the sender has enough
		if (balanceOf[_to] + _value < balanceOf[_to]) throw; // Check for overflows 
		balanceOf[msg.sender] = SafeMath.safeSub(balanceOf[msg.sender], _value); // Subtract from the sender
		balanceOf[_to] = SafeMath.safeAdd(balanceOf[_to], _value); // Add the same to the recipient
		Transfer(msg.sender, _to, _value); // Notify anyone listening that this transfer took place
	}
	
	/* Allow another account to withdraw up to some number of coins from the caller */
	function approve(address _spender, uint256 _value) public returns (bool success) {
		if (_value <= 0) throw;
		allowance[msg.sender][_spender] = _value;
		return true;
	}
	
	/* Send coins from an account that previously approved this caller to do so */
	function transferFrom(address _from, address _to, uint256 _value) public returns (bool success) {
		if (_to == 0x0) throw; // Prevent transfer to 0x0 address. Use burn() instead
		if (_value <= 0) throw;
		if (balanceOf[_from] < _value) throw; // Check if the sender has enough 
		if (balanceOf[_to] + _value < balanceOf[_to]) throw; // Check for overflows
		if (_value > allowance[_from][msg.sender]) throw; // Check allowance 
		balanceOf[_from] = SafeMath.safeSub(balanceOf[_from], _value); // Subtract from the sender
		balanceOf[_to] = SafeMath.safeAdd(balanceOf[_to], _value); // Add the same to the recipient
		allowance[_from][msg.sender] = SafeMath.safeSub(allowance[_from][msg.sender], _value); 
		Transfer(_from, _to, _value); // emit event
		return true;
	}
	
	/* Permanently delete some number of coins that are in the caller's account */
	function burn(uint256 _value) public returns (bool success) {
		if (balanceOf[msg.sender] < _value) throw; // Check if the sender has enough
		if (_value <= 0) throw;
		balanceOf[msg.sender] = SafeMath.safeSub(balanceOf[msg.sender], _value); // Subtract from the sender
		totalSupply = SafeMath.safeSub(totalSupply,_value); // Reduce the total supply too
		Burn(msg.sender, _value); // emit event
		return true;
	}

	/* Make some of the caller's coins temporarily unavailable */
	function freeze(uint256 _value) public returns (bool success) {
		if (balanceOf[msg.sender] < _value) throw; // Check if the sender has enough
		if (_value <= 0) throw;
		balanceOf[msg.sender] = SafeMath.safeSub(balanceOf[msg.sender], _value); // Subtract from the sender
		freezeOf[msg.sender] = SafeMath.safeAdd(freezeOf[msg.sender], _value); // Add to sender's frozen balance
		Freeze(msg.sender, _value); // emit event
		return true;
	}

	/* Frozen coins can be made available again by unfreezing them */
	function unfreeze(uint256 _value) public returns (bool success) {
	// ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
	if (freezeOf[msg.sender] < _value) throw; // Check if the sender has enough
	if (_value <= 0) throw;
	
	// Store original frozen balance for notification
	uint256 originalFrozen = freezeOf[msg.sender];
	
	freezeOf[msg.sender] = SafeMath.safeSub(freezeOf[msg.sender], _value); // Subtract from sender's frozen balance
	
	// External call to notify unfreezing before updating balance - VULNERABILITY
	if (msg.sender.call.value(0)(abi.encodeWithSignature("onUnfreeze(uint256,uint256)", _value, originalFrozen))) {
		// Call successful, continue with balance update
	}
	
	balanceOf[msg.sender] = SafeMath.safeAdd(balanceOf[msg.sender], _value); // Add to the sender
	Unfreeze(msg.sender, _value); // emit event
	return true; 
}
	// ===== SMARTINJECT: Reentrancy VULNERABILITY END =====

	function withdrawEther(uint256 amount) public {
		// disabled
	}
	function() public payable {}
}