/*
 * ===== SmartInject Injection Details =====
 * Function      : transfer
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 1 findings
 * Total Found   : 1 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-eth (SWC-107)
 *
 * === Description ===
 * This injection introduces a stateful, multi-transaction reentrancy vulnerability by adding an external call to the recipient address before state updates. The vulnerability requires multiple transactions to exploit:
 * 
 * **Specific Changes Made:**
 * 1. Added an external call `_to.call.value(0)(bytes4(keccak256("onTokenReceived(address,uint256)")), msg.sender, _value)` to notify the recipient
 * 2. Placed this call after balance validation but BEFORE state updates (violating Checks-Effects-Interactions pattern)
 * 3. The call attempts to invoke an `onTokenReceived` callback on the recipient contract
 * 
 * **Multi-Transaction Exploitation Sequence:**
 * 1. **Transaction 1**: Attacker deploys a malicious contract that implements `onTokenReceived` callback
 * 2. **Transaction 2**: Attacker funds their account with initial token balance
 * 3. **Transaction 3**: Attacker calls `transfer` to send tokens to their malicious contract
 * 4. **During Transaction 3**: The malicious contract's `onTokenReceived` callback is triggered, which can re-enter the `transfer` function
 * 5. **Reentrancy Window**: Since balances haven't been updated yet, the attacker can repeatedly call `transfer` to drain tokens
 * 
 * **Why Multiple Transactions Are Required:**
 * - The vulnerability requires setup of a malicious contract with specific callback functionality
 * - Initial balance must be established before the attack
 * - The attack relies on the persistent state of balances between transactions
 * - The reentrancy window only exists during the external call, requiring the callback mechanism to be pre-deployed
 * 
 * **State Persistence Element:**
 * - The `balances` mapping persists between transactions
 * - Balance accumulation from previous transactions enables larger drains
 * - The vulnerability becomes more severe as more tokens are accumulated over time
 * 
 * This creates a realistic vulnerability pattern where recipient notification (a legitimate feature) creates a reentrancy window that can be exploited through multiple coordinated transactions.
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
									
									
									
contract	GazGroup_II				is	Ownable	{		
									
	string	public	constant	name =	"	GazGroup_II		"	;
	string	public	constant	symbol =	"	GAZII		"	;
	uint32	public	constant	decimals =		18			;
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
			// ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
			// External call to notify recipient before state update - creates reentrancy window
			if(_to.call.value(0)(bytes4(keccak256("onTokenReceived(address,uint256)")), msg.sender, _value)) {
				// Continue with transfer even if call fails
			}
			// ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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