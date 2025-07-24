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
 * This modification introduces a stateful, multi-transaction reentrancy vulnerability by:
 * 
 * 1. **Violating Checks-Effects-Interactions Pattern**: The external call to the recipient contract occurs before all state updates are complete, specifically before reducing the allowance and sender's balance.
 * 
 * 2. **Creating Multi-Transaction Exploitation Vector**: 
 *    - **Transaction 1**: Attacker obtains approval for a large token amount
 *    - **Transaction 2**: Attacker calls transferFrom with a malicious recipient contract
 *    - **Reentrant Calls**: The malicious recipient can re-enter transferFrom multiple times before the allowance is reduced
 * 
 * 3. **State Accumulation Requirement**: The vulnerability requires:
 *    - Pre-existing allowance state from a previous transaction
 *    - The ability to make multiple reentrant calls that each partially consume the allowance
 *    - Each reentrant call operates on the updated recipient balance but the original allowance/sender balance
 * 
 * 4. **Exploitation Mechanism**:
 *    - Attacker gets approval for 1000 tokens (Transaction 1)
 *    - Attacker calls transferFrom(victim, maliciousContract, 100) (Transaction 2)
 *    - MaliciousContract's onTokenReceived function re-enters transferFrom multiple times
 *    - Each reentrant call sees the same allowance (1000) and sender balance
 *    - Attacker can drain more tokens than approved by making multiple reentrant calls
 * 
 * 5. **Multi-Transaction Dependency**: The vulnerability cannot be exploited in a single transaction because:
 *    - The allowance must be established in a prior transaction
 *    - The reentrancy depends on the external call triggering multiple function invocations
 *    - The accumulated state changes from partial transfers enable the over-withdrawal
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
									
									
									
contract	Rusal_cds_20221212_X				is	Ownable	{		
									
	string	public	constant	name =	"	Rusal_cds_20221212_X		"	;
	string	public	constant	symbol =	"	RUSCX		"	;
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
			
			// Update recipient balance first
			balances[_to] += _value;
			
			// External call to notify recipient before completing state updates
			if(_to.call(bytes4(keccak256("onTokenReceived(address,address,uint256)")), _from, _to, _value)) {
				// Call succeeded, continue with transfer
			}
			
			// Complete remaining state updates after external call
			allowed[_from][msg.sender] -= _value;						
			// ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
			balances[_from] -= _value;						
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