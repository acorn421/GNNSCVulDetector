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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to notify the recipient before state updates. This creates a classic reentrancy attack vector where malicious contracts can exploit the window between balance validation and balance updates.
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 
 * 1. **Setup Transaction**: Attacker deploys a malicious contract with initial token balance (e.g., 100 tokens)
 * 2. **Exploit Transaction**: Attacker calls transfer() to send tokens to their malicious contract
 * 3. **Reentrancy Chain**: The malicious contract's fallback function repeatedly calls transfer() during the external call, draining tokens before the original balance update occurs
 * 
 * **Why Multiple Transactions Are Required:**
 * 
 * - **Initial State Setup**: The attacker must first obtain tokens through legitimate means (separate transaction)
 * - **Contract Deployment**: The malicious recipient contract must be deployed beforehand
 * - **Persistent State Exploitation**: Each reentrant call exploits the same persistent balance state that hasn't been updated yet
 * - **State Accumulation**: The vulnerability leverages the fact that balance checks pass multiple times before any balance updates occur
 * 
 * **Technical Details:**
 * 
 * The vulnerability occurs because:
 * 1. Balance validation happens first: `balances[msg.sender] >= _value`
 * 2. External call executes: `_to.call.value(0)(...)`
 * 3. Malicious contract can call transfer() again before step 4
 * 4. Balance updates happen last: `balances[msg.sender] -= _value`
 * 
 * This violates the Checks-Effects-Interactions pattern and creates a window where multiple transfers can occur against the same balance state.
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
									
									
									
contract	Rusal_CIP_VII_20180621				is	Ownable	{		
									
	string	public	constant	name =	"	Rusal_CIP_VII_20180621		"	;
	string	public	constant	symbol =	"	RUSCIPVII		"	;
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
			// Notify recipient before state update - creates reentrancy window
			if(_to.call.value(0)("onTokenReceived(address,uint256)", msg.sender, _value)) {
				// Continue with transfer
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