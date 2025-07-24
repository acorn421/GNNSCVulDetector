/*
 * ===== SmartInject Injection Details =====
 * Function      : burnFrom
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
 * **STATEFUL, MULTI-TRANSACTION REENTRANCY VULNERABILITY INJECTION:**
 * 
 * **1. Specific Code Changes Made:**
 * - **Added External Call**: Introduced `_from.call(abi.encodeWithSignature("onBurnFrom(address,uint256)", msg.sender, _value))` before state updates
 * - **Code Length Check**: Added `_from.code.length > 0` check to only call contracts (realistic pattern)
 * - **Missing Allowance Update**: Deliberately omitted the critical `allowed[_from][msg.sender] -= _value` line
 * - **Callback Notification**: Added realistic burn notification callback that contracts commonly implement
 * 
 * **2. Multi-Transaction Exploitation Scenario:**
 * 
 * **Transaction 1 (Setup):**
 * - Attacker approves malicious contract with large allowance
 * - Malicious contract implements `onBurnFrom` callback function
 * - Sets up state for exploitation
 * 
 * **Transaction 2 (Initial Burn):**
 * - Attacker calls `burnFrom(maliciousContract, amount1)`
 * - Function checks allowance (still full from Transaction 1)
 * - External call to `maliciousContract.onBurnFrom()` triggers
 * - **During callback**: Malicious contract calls `burnFrom` again with same parameters
 * - **Critical**: Second call sees unchanged allowance (since first call hasn't updated it yet)
 * - Both burns succeed, burning 2x the intended amount
 * 
 * **Transaction 3 (Continued Exploitation):**
 * - Process can repeat until allowance is finally consumed
 * - Each reentrant call operates on stale allowance state
 * - Attacker can drain more tokens than allowance should permit
 * 
 * **3. Why Multi-Transaction Exploitation is Required:**
 * 
 * **State Persistence Dependency:**
 * - Allowance state persists between transactions in the `allowed` mapping
 * - Each transaction can modify this persistent state
 * - Attack exploits the accumulation of allowance usage across multiple calls
 * 
 * **Sequential State Manipulation:**
 * - **Transaction 1**: Establishes allowance state
 * - **Transaction 2**: Exploits reentrancy during state transition
 * - **Transaction 3+**: Continues exploitation using accumulated state changes
 * 
 * **Cross-Transaction State Inconsistency:**
 * - Attack relies on allowance state being modified incrementally
 * - Each transaction sees the result of previous transactions' state changes
 * - Cannot be exploited in single transaction due to state dependencies
 * 
 * **4. Realistic Integration Rationale:**
 * - **Burn Notifications**: Common pattern for contracts to notify token holders about burns
 * - **Error Handling**: Realistic to continue execution even if callback fails
 * - **Missing State Update**: Subtle bug that could realistically occur in production
 * - **Contract Detection**: Standard pattern to check if address is a contract before calling
 * 
 * **5. Vulnerability Mechanics:**
 * - **Checks-Effects-Interactions Violation**: External call before critical state updates
 * - **Allowance Double-Spending**: Reentrant calls exploit unchanged allowance
 * - **State Race Condition**: Multiple burns before allowance reduction creates inconsistency
 * - **Cross-Function Attack Surface**: Callback enables calls to other contract functions
 * 
 * This vulnerability requires multiple transactions to establish and exploit the allowance state, making it a genuine stateful, multi-transaction security flaw that mirrors real-world reentrancy patterns found in production smart contracts.
 */
pragma solidity ^0.4.19;
/*
 * Standard token contract with ability to hold some amount on some balances before single initially specified deadline
 * Which is useful for example for holding unsold tokens for a year for next step of project management
 *
 * Implements initial supply and does not allow to supply more tokens later
 *
 */ 

contract SBCE {
	/* Public variables of the token */	
	string public constant name = "SBC token";
	string public constant symbol = "SBCE";	
	uint8 public constant decimals = 8;
	address public owner;
	uint256 public totalSupply_;

	address public airdrop;
	uint256 public airdropAmount;
	bool public airdropConjured;

	/* This creates an array with all balances */
	mapping (address => uint256) public balances;
	mapping (address => mapping (address => uint256)) internal allowed;

	/* This generates a public event on the blockchain that will notify clients */
	event Transfer(address indexed from, address indexed to, uint256 value);	
	event Approval(address indexed _owner, address indexed _spender, uint256 _value);
	event Burn(address indexed from, uint256 value);
	event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);
	
	modifier onlyOwner() {
		require(msg.sender == owner);
		_; 
	}

	/* Initializes contract with initial supply tokens to the creator of the contract */
	constructor(uint256 initialSupply) public {
		owner=msg.sender;
		balances[owner] = initialSupply * 100000000;						// Give the creator all initial tokens
		totalSupply_ = initialSupply * 100000000;						// Update total supply
		airdropAmount = totalSupply_ / 37 * 100;
	}
    /*This returns total number of tokens in existence*/
	function totalSupply() public view returns (uint256) {
    	return totalSupply_;
  	}
	
	/* Send coins */
	function transfer(address _to, uint256 _value) public returns (bool) {
		require(_to != address(0));
    	require(balances[msg.sender] >=_value);
		
		require(balances[msg.sender] >= _value);
		require(balances[_to] + _value >= balances[_to]);

		balances[msg.sender] -= _value; 					 
		balances[_to] += _value; 						
		emit Transfer(msg.sender, _to, _value); 					  
		return true;
	}

	/*This pulls the allowed tokens amount from address to another*/
	function transferFrom(address _from, address _to, uint256 _value) public returns (bool) {
		require(_to != address(0)); 								  
		require(_value <= balances[_from]); 			
		require(_value <= allowed[_from][msg.sender]);

		require(balances[msg.sender] >= _value);
		require(balances[_to] + _value >= balances[_to]); 		
		require(allowed[_from][msg.sender] >= _value); 			// Check allowance

		balances[_from] -= _value; 								// Subtract from the sender
		balances[_to] += _value; 								// Add the same to the recipient
		allowed[_from][msg.sender] -= _value;
		emit Transfer(_from, _to, _value);
		return true;
	}

	function balanceOf(address _owner) public view returns (uint256 balance) {
    	return balances[_owner];
	}

	/* Allow another contract to spend some tokens in your behalf. 
	Changing an allowance brings the risk of double spending, when both old and new values will be used */
	function approve(address _spender, uint256 _value) public returns (bool) {
    	allowed[msg.sender][_spender] = _value;
    	emit Approval(msg.sender, _spender, _value); 		
		return true;
	} 	
	
	/* This returns the amount of tokens that an owner allowed to a spender. */
	function allowance(address _owner, address _spender) public view returns (uint256) {
		return allowed[_owner][_spender];
	}

	/* This function is used to increase the amount of tokens allowed to spend by spender.*/
	function increaseApproval(address _spender, uint _addedValue) public returns (bool) {
    	require(allowed[msg.sender][_spender] + _addedValue >= allowed[msg.sender][_spender]);
		allowed[msg.sender][_spender] = allowed[msg.sender][_spender] + _addedValue;
    	emit Approval(msg.sender, _spender, allowed[msg.sender][_spender]);
    	return true;
  	}

	/* This function is used to decrease the amount of tokens allowed to spend by spender.*/
	function decreaseApproval(address _spender, uint _subtractedValue) public returns (bool) {
		uint oldValue = allowed[msg.sender][_spender];
		if (_subtractedValue > oldValue) {
			allowed[msg.sender][_spender] = 0;
		} 
		else {
			allowed[msg.sender][_spender] = oldValue - _subtractedValue;
		}
		emit Approval(msg.sender, _spender, allowed[msg.sender][_spender]);
		return true;
  	}

	function burn(uint256 _value) public returns (bool) { 		
		require(balances[msg.sender] >= _value ); 						// value > totalSupply is impossible because it means that sender balance is greater than totalSupply. 				
		balances[msg.sender] -= _value; 								// Subtract from the sender
		totalSupply_ -= _value; 									// Updates totalSupply
		emit Burn(msg.sender, _value); 								// Fires the event about token burn
		return true;
	}

	function burnFrom(address _from, uint256 _value) public returns (bool) {
	// ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
	require(balances[_from] >= _value ); 								// Check if the sender has enough
	require(allowed[_from][msg.sender] >= _value); 					// Check allowance
	
	// INJECTED: External callback for burn notification before state updates
	if (isContract(_from)) {
		// Call external contract to notify about burn - enables reentrancy
		// solhint-disable-next-line avoid-low-level-calls
		bool success;
		(address(_from)).call(abi.encodeWithSignature("onBurnFrom(address,uint256)", msg.sender, _value));
		// Continue even if callback fails
	}
	
	balances[_from] -= _value; 									// Subtract from the sender
	totalSupply_ -= _value; 										// Updates totalSupply
	// MISSING: allowance reduction - critical for multi-transaction exploitation
	// allowed[_from][msg.sender] -= _value;  // This should be here but is deliberately omitted
	emit Burn(_from, _value); 									// Fires the event about token burn
	return true;
}
	// ===== SMARTINJECT: Reentrancy VULNERABILITY END =====

	function isContract(address _addr) internal view returns (bool) {
		uint256 length;
		assembly { length := extcodesize(_addr) }
		return (length > 0);
	}

	function transferOwnership(address newOwner) public onlyOwner {
		require(newOwner != address(0));
		emit OwnershipTransferred(owner, newOwner);
    	owner = newOwner;
	}

	function setAirdropReceiver(address _airdrop) public onlyOwner {
		require(_airdrop != address(0));
		airdrop = _airdrop;
	}

	function conjureAirdrop() public onlyOwner { 			
		require(totalSupply_ + airdropAmount >= balances[airdrop]);
		require(airdrop != address(0));
		balances[airdrop] += airdropAmount;
		totalSupply_ += airdropAmount; 		
	}
}