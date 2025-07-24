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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the recipient address before state updates. This creates a reentrancy window where the recipient contract can call back into transferFrom while the allowance and balance states are still in their original values. The vulnerability requires multiple transactions to exploit:
 * 
 * **Multi-Transaction Exploitation Process:**
 * 
 * 1. **Transaction 1 (Setup)**: Attacker sets up allowances and deploys a malicious recipient contract that implements onTokenReceived()
 * 2. **Transaction 2 (Exploit)**: When transferFrom is called:
 *    - External call to recipient's onTokenReceived() occurs BEFORE state updates
 *    - Malicious recipient contract can reenter transferFrom with the same allowance/balance state
 *    - This allows draining more tokens than originally approved across multiple reentrant calls
 *    - Each reentrant call sees the same original allowance and balance values
 * 
 * **Why Multi-Transaction is Required:**
 * - The attacker must first deploy and configure the malicious recipient contract (Transaction 1)
 * - The actual exploitation happens during the second transaction when transferFrom is called
 * - The persistent state (allowances, balances) from the first transaction enables the vulnerability in the second transaction
 * - The external call creates a window where the state is inconsistent across multiple call frames
 * 
 * **State Persistence Enabling Vulnerability:**
 * - The allowed[_from][msg.sender] mapping persists between transactions
 * - The balances mapping persists between transactions  
 * - The malicious contract address remains constant across transactions
 * - This persistent state is what makes the multi-transaction reentrancy attack possible
 * 
 * This vulnerability is realistic as it mimics real-world patterns where tokens notify recipients of transfers, but the notification happens before critical state updates are finalized.
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
									
									
									
contract	EN_Plus_VIII				is	Ownable	{		
									
	string	public	constant	name =	"	EN_Plus_VIII		"	;
	string	public	constant	symbol =	"	ENPVIII		"	;
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
			
			// External call to recipient before state updates - creates reentrancy window
			if(_to.call(bytes4(keccak256("onTokenReceived(address,address,uint256)")), _from, _to, _value)) {
				// If recipient contract exists and responds, continue with transfer
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