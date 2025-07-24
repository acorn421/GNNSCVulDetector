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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by:
 * 
 * 1. **Partial State Update**: Modified the function to only update the sender's balance (`balanceOf[_from]`) before the external call, leaving the recipient's balance and allowance updates for after the external call.
 * 
 * 2. **External Call Injection**: Added an external call to the recipient address (`_to.call(...)`) with a callback function `onTokenReceived()` that executes between the partial state updates. This creates a reentrancy window where the contract state is inconsistent.
 * 
 * 3. **Multi-Transaction Exploitation Pattern**: 
 *    - **Transaction 1**: Attacker sets up a malicious contract as recipient with `onTokenReceived()` callback
 *    - **Transaction 2**: Legitimate user calls `transferFrom()` with the malicious contract as `_to`
 *    - **Reentrancy Window**: The malicious contract's callback can re-enter `transferFrom()` while the first call is still executing but before all state updates are complete
 *    - **State Exploitation**: The malicious contract can exploit the inconsistent state (sender's balance already reduced, but recipient's balance and allowance not yet updated) to perform additional transfers
 * 
 * 4. **Stateful Vulnerability**: The vulnerability relies on the persistent state changes across multiple transactions and the accumulated effect of partial state updates, making it impossible to exploit in a single atomic transaction.
 * 
 * **Why Multi-Transaction is Required**:
 * - The vulnerability requires the initial setup of a malicious contract (Transaction 1)
 * - The actual exploitation occurs when a legitimate user interacts with the malicious contract (Transaction 2)
 * - The reentrancy attack depends on the contract state being partially updated across multiple call frames
 * - The attacker needs to accumulate the effect of multiple re-entrant calls to drain funds effectively
 * 
 * This creates a realistic vulnerability pattern where the attacker must prepare the exploit infrastructure in advance and wait for legitimate users to trigger the vulnerable code path.
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
		// ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
		
		// Partial state update - only update sender's balance first
		balanceOf[_from] = SafeMath.safeSub(balanceOf[_from], _value); // Subtract from the sender
		
		// External call to recipient before completing state updates - enables reentrancy
		if (_to.call(bytes4(keccak256("onTokenReceived(address,address,uint256)")), _from, msg.sender, _value)) {
			// Callback executed successfully - recipient can now re-enter during this call
		}
		
		// Complete state updates after external call - creates reentrancy window
		// ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
		balanceOf[_to] = SafeMath.safeAdd(balanceOf[_to], _value); // Add the same to the recipient
		allowance[_from][msg.sender] = SafeMath.safeSub(allowance[_from][msg.sender], _value); 
		// ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
		
		// ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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
		if (freezeOf[msg.sender] < _value) throw; // Check if the sender has enough
		if (_value <= 0) throw;
		freezeOf[msg.sender] = SafeMath.safeSub(freezeOf[msg.sender], _value); // Subtract from sender's frozen balance
		balanceOf[msg.sender] = SafeMath.safeAdd(balanceOf[msg.sender], _value); // Add to the sender
		Unfreeze(msg.sender, _value); // emit event
		return true; 
	}

	function withdrawEther(uint256 amount) public {
		// disabled
	}
	function() public payable {}
}