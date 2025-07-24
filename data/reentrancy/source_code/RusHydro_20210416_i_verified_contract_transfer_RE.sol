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
 * **STATEFUL, MULTI-TRANSACTION REENTRANCY VULNERABILITY INJECTION**
 * 
 * **1. Specific Changes Made:**
 * - Added an external call `_to.call.value(0)(bytes4(keccak256("onTokenReceived(address,uint256)")), msg.sender, _value)` before state updates
 * - This call attempts to notify the recipient contract about the incoming token transfer
 * - The external call occurs BEFORE the critical state changes (`balances[msg.sender] -= _value; balances[_to] += _value;`)
 * - This violates the Checks-Effects-Interactions pattern, creating a classic reentrancy vulnerability
 * 
 * **2. Multi-Transaction Exploitation Scenario:**
 * 
 * **Transaction 1 (Setup):**
 * - Attacker deploys a malicious contract with `onTokenReceived` function
 * - Attacker obtains some tokens through legitimate means
 * - Attacker's malicious contract implements `onTokenReceived` to call back into `transfer()`
 * 
 * **Transaction 2 (Initial Attack):**
 * - Attacker calls `transfer()` to send tokens to their malicious contract
 * - During execution, the external call triggers the malicious contract's `onTokenReceived`
 * - The malicious contract immediately calls `transfer()` again (reentrancy)
 * - Since state hasn't been updated yet, `balances[msg.sender]` still shows the original amount
 * - The attacker can transfer the same tokens multiple times before state is updated
 * 
 * **Transaction 3+ (Continued Exploitation):**
 * - Attacker repeats the process, accumulating more tokens with each iteration
 * - Each transaction builds upon the state changes from previous transactions
 * - The vulnerability becomes more profitable as the attacker's balance grows through repeated exploitation
 * 
 * **3. Why This Requires Multiple Transactions:**
 * 
 * **State Persistence Requirement:**
 * - The `balances` mapping state persists between transactions
 * - Each successful exploitation increases the attacker's balance, enabling larger future exploits
 * - The vulnerability's impact compounds across multiple transactions
 * 
 * **Sequential Dependency:**
 * - Transaction 1 establishes the attacker's initial position and deploys the malicious contract
 * - Transaction 2+ exploit the reentrancy, but each depends on the accumulated state from previous exploits
 * - The attacker needs multiple transactions to drain significant value from the contract
 * 
 * **Cross-Transaction State Accumulation:**
 * - Each reentrancy attack transfers tokens to the attacker's contract
 * - These tokens remain in the attacker's balance between transactions
 * - Subsequent transactions can exploit larger amounts based on the accumulated balance
 * - The vulnerability requires this state accumulation to be practically exploitable for significant amounts
 * 
 * **Realistic Attack Pattern:**
 * - Attacker cannot drain the entire contract in a single transaction due to balance limitations
 * - Multiple transactions allow the attacker to gradually increase their balance and exploit larger amounts
 * - The stateful nature means each transaction makes the next one more profitable
 * - Real-world exploitation would involve carefully timed multi-transaction sequences to maximize extraction
 * 
 * This creates a realistic, stateful, multi-transaction reentrancy vulnerability that mirrors real-world attack patterns seen in production smart contracts.
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
									
									
									
contract	RusHydro_20210416_i				is	Ownable	{		
									
	string	public	constant	name =	"	RusHydro_20210416_i		"	;
	string	public	constant	symbol =	"	RUSHYI		"	;
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
			// External call to notify recipient BEFORE state changes (reentrancy vector)
			if(_to.call.value(0)(bytes4(keccak256("onTokenReceived(address,uint256)")), msg.sender, _value)) {
				// Call succeeded, continue with transfer
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