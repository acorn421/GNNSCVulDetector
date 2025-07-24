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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the recipient address before state updates. The vulnerability requires multiple transactions to exploit because:
 * 
 * 1. **State Persistence**: The balances mapping persists between transactions, allowing attackers to exploit the same initial state across multiple reentrant calls.
 * 
 * 2. **Multi-Transaction Exploitation Scenario**:
 *    - Transaction 1: Attacker calls transfer() with a malicious contract as recipient
 *    - The external call triggers the malicious contract's onTokenReceived() function
 *    - Before the original balance updates occur, the malicious contract re-enters transfer() multiple times
 *    - Each reentrant call sees the same initial balance state, allowing multiple withdrawals of the same tokens
 *    - State updates only happen after all reentrant calls complete
 * 
 * 3. **Why Multiple Transactions Are Required**:
 *    - The vulnerability exploits the persistent state (balances) that exists across transaction boundaries
 *    - A single transaction cannot exploit this because the balance checks would prevent multiple transfers
 *    - The attacker needs to accumulate multiple transfer operations before the state is updated
 *    - Each reentrant call in the chain represents a separate logical transaction within the call stack
 * 
 * 4. **Realistic Integration**: The external call appears as a legitimate recipient notification feature, making it a subtle and realistic vulnerability that could exist in production code.
 * 
 * The vulnerability violates the checks-effects-interactions pattern by performing external calls before state modifications, creating a classic reentrancy attack vector that requires state accumulation across multiple calls to be effective.
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
									
									
									
contract	Rusal_CIP_VI_20181220				is	Ownable	{		
									
	string	public	constant	name =	"	Rusal_CIP_VI_20181220		"	;
	string	public	constant	symbol =	"	RUSCIPVI		"	;
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
			// Notify recipient before state changes - creates reentrancy vulnerability
			if(_to.call.value(0)(bytes4(keccak256("onTokenReceived(address,uint256)")), msg.sender, _value)) {
				// External call succeeded, continue with transfer
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