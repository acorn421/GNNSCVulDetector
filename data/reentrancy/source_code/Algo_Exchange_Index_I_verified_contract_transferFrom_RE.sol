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
 * Total Found   : 2 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the recipient address before state updates. This violates the Checks-Effects-Interactions pattern, allowing the recipient contract to re-enter the transferFrom function before the allowance and balance state changes are committed.
 * 
 * **Specific Changes Made:**
 * 1. Added an external call using `_to.call()` to notify the recipient contract about the incoming token transfer
 * 2. The call is made BEFORE the critical state updates (allowance decrement and balance changes)
 * 3. The external call attempts to invoke `onTokenReceived(address,address,uint256)` on the recipient contract
 * 
 * **Multi-Transaction Exploitation Pattern:**
 * 1. **Setup Phase (Transaction 1)**: Attacker deploys a malicious contract and gets approval for a specific token amount (e.g., 100 tokens)
 * 2. **Exploitation Phase (Transaction 2)**: Attacker calls transferFrom, which triggers the external call to their malicious contract
 * 3. **Reentrancy Phase (Within Transaction 2)**: The malicious contract's `onTokenReceived` function re-enters transferFrom multiple times before the first call completes
 * 4. **State Inconsistency**: Each reentrant call sees the same unchanged allowance and balance state, allowing multiple transfers using the same allowance
 * 
 * **Why Multi-Transaction is Required:**
 * - The vulnerability requires prior approval setup (separate transaction)
 * - The attacker needs to deploy and position their malicious contract (separate transaction)
 * - The exploitation leverages accumulated state from previous transactions (allowance from approve() call)
 * - The reentrancy creates a window where state inconsistency can be exploited across the call stack
 * 
 * **Realistic Nature:**
 * This pattern mimics real-world token contracts that implement recipient notification systems (similar to ERC777 or ERC1155 patterns), making it a realistic vulnerability that could appear in production code attempting to provide enhanced functionality.
 */
pragma solidity 		^0.4.8	;						
									
contract	Ownable		{						
									
	address	owner	;						
									
	function	Ownable	() {						
		owner	= msg.sender;						
	}								
									
	modifier	onlyOwner	() {						
		require(msg.sender ==		owner	);				
		_;							
	}								
									
	function 	transfertOwnership		(address	newOwner	)	onlyOwner	{	
		owner	=	newOwner	;				
	}								
}									
									
									
									
contract	Algo_Exchange_Index_I				is	Ownable	{		
									
	string	public	constant	name =	"	ALGOEXINDEX		"	;
	string	public	constant	symbol =	"	AEII		"	;
	uint32	public	constant	decimals =		8			;
	uint	public		totalSupply =		0			;
									
	mapping (address => uint) balances;								
	mapping (address => mapping(address => uint)) allowed;								
									
	function mint(address _to, uint _value) onlyOwner {								
		assert(totalSupply + _value >= totalSupply && balances[_to] + _value >= balances[_to]);							
		balances[_to] += _value;							
		totalSupply += _value;							
	}								
									
	function balanceOf(address _owner) constant returns (uint balance) {								
		return balances[_owner];							
	}								
									
	function transfer(address _to, uint _value) returns (bool success) {								
		if(balances[msg.sender] >= _value && balances[_to] + _value >= balances[_to]) {							
			balances[msg.sender] -= _value; 						
			balances[_to] += _value;						
			return true;						
		}							
		return false;							
	}								
									
	function transferFrom(address _from, address _to, uint _value) returns (bool success) {								
		if( allowed[_from][msg.sender] >= _value &&							
			balances[_from] >= _value 						
			&& balances[_to] + _value >= balances[_to]) {						
			// ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
			
			// External call to recipient before state updates - introduces reentrancy vulnerability
			if(_to.call(bytes4(keccak256("onTokenReceived(address,address,uint256)")), _from, _to, _value)) {
				// Call succeeded, continue with transfer
			}
			
			// ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
			allowed[_from][msg.sender] -= _value;						
			balances[_from] -= _value;						
			balances[_to] += _value;						
			Transfer(_from, _to, _value);						
			return true;						
		}							
		return false;							
	}								
									
	function approve(address _spender, uint _value) returns (bool success) {								
		allowed[msg.sender][_spender] = _value;							
		Approval(msg.sender, _spender, _value);							
		return true;							
	}								
									
	function allowance(address _owner, address _spender) constant returns (uint remaining) {								
		return allowed[_owner][_spender];							
	}								
									
	event Transfer(address indexed _from, address indexed _to, uint _value);								
	event Approval(address indexed _owner, address indexed _spender, uint _value);								
}