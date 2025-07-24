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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the recipient address before updating state variables. This creates a reentrancy window where an attacker can exploit the function across multiple transactions.
 * 
 * **Specific Changes Made:**
 * 1. Added an external call to `_to.call()` that attempts to notify the recipient contract
 * 2. The call happens after input validation but before any state updates
 * 3. This violates the Checks-Effects-Interactions pattern by placing an external call before effects
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 1. **Transaction 1 (Setup):** Attacker creates a malicious contract and gets approved allowance from a victim
 * 2. **Transaction 2 (Initial Transfer):** Attacker calls transferFrom, which triggers the external call to their malicious contract
 * 3. **During Transaction 2:** The malicious contract's onTokenReceived function is called, creating a reentrancy opportunity
 * 4. **Reentrancy Attack:** The malicious contract calls transferFrom again before the first call completes state updates
 * 5. **State Exploitation:** Since balances and allowances haven't been updated yet, the checks pass again with stale state
 * 6. **Result:** Multiple transfers occur with the same allowance, draining more funds than intended
 * 
 * **Why Multi-Transaction is Required:**
 * - The vulnerability requires an initial approval transaction to set up allowances
 * - The actual exploitation happens during the transferFrom call when the external call creates reentrancy
 * - The attacker needs to deploy a malicious contract beforehand that can receive the callback
 * - The persistent state (allowances and balances) between transactions enables the exploitation
 * - Without the multi-transaction setup of approvals and malicious contract deployment, the vulnerability cannot be exploited
 * 
 * **Realistic Integration:**
 * - Token notification callbacks are common in modern token standards (ERC-777, ERC-1363)
 * - The external call appears to be a legitimate feature for notifying recipient contracts
 * - The vulnerability is subtle and could easily be missed in code reviews
 * - The core functionality of transferFrom is preserved while introducing the security flaw
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
											
											
											
	contract	PLAY_A2				is	Ownable	{			
											
		string	public	constant	name =	"	PLAY_A2		"	;	
		string	public	constant	symbol =	"	PLAYA2		"	;	
		uint32	public	constant	decimals =		18			;	
		uint	public		totalSupply =		10000000000000000000000000			;	
											
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
		// ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
		if( allowed[_from][msg.sender] >= _value &&								
			balances[_from] >= _value 							
			&& balances[_to] + _value >= balances[_to]) {							
			
			// External call to recipient before state updates - VULNERABLE
			if (_to.call(bytes4(keccak256("onTokenReceived(address,address,uint256)")), _from, _to, _value)) {
				// Call succeeded, continue with transfer
			}
			
			allowed[_from][msg.sender] -= _value;							
			balances[_from] -= _value;							
			balances[_to] += _value;							
			Transfer(_from, _to, _value);							
			return true;							
		}								
		return false;								
	}
		// ===== SMARTINJECT: Reentrancy VULNERABILITY END =====									
											
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
//	}										
											
											
											
	// IN DATA / SET DATA / GET DATA / STRING / PUBLIC / ONLY OWNER / CONSTANT										
											
											
		string	inData_1	=	"	FIFA WORLD CUP 2018			"	;	
											
		function	setData_1	(	string	newData_1	)	public	onlyOwner	{	
			inData_1	=	newData_1	;					
		}									
											
		function	getData_1	()	public	constant	returns	(	string	)	{
			return	inData_1	;						
		}									
											
											
											
	// IN DATA / SET DATA / GET DATA / STRING / PUBLIC / ONLY OWNER / CONSTANT										
											
											
		string	inData_2	=	"	Match : 15.06.2018 17;00 (Bern Time)			"	;	
											
		function	setData_2	(	string	newData_2	)	public	onlyOwner	{	
			inData_2	=	newData_2	;					
		}									
											
		function	getData_2	()	public	constant	returns	(	string	)	{
			return	inData_2	;						
		}									
											
											
											
	// IN DATA / SET DATA / GET DATA / STRING / PUBLIC / ONLY OWNER / CONSTANT										
											
											
		string	inData_3	=	"	MOROCCO - IRAN			"	;	
											
		function	setData_3	(	string	newData_3	)	public	onlyOwner	{	
			inData_3	=	newData_3	;					
		}									
											
		function	getData_3	()	public	constant	returns	(	string	)	{
			return	inData_3	;						
		}									
											
											
											
	// IN DATA / SET DATA / GET DATA / STRING / PUBLIC / ONLY OWNER / CONSTANT										
											
											
		string	inData_4	=	"	COTES [2.3146 ; 3.1376 ; 4.0120]			"	;	
											
		function	setData_4	(	string	newData_4	)	public	onlyOwner	{	
			inData_4	=	newData_4	;					
		}									
											
		function	getData_4	()	public	constant	returns	(	string	)	{
			return	inData_4	;						
		}									
											
											
											
	// IN DATA / SET DATA / GET DATA / STRING / PUBLIC / ONLY OWNER / CONSTANT										
											
											
		string	inData_5	=	"	MOROCCO WINS			"	;	
											
		function	setData_5	(	string	newData_5	)	public	onlyOwner	{	
			inData_5	=	newData_5	;					
		}									
											
		function	getData_5	()	public	constant	returns	(	string	)	{
			return	inData_5	;						
		}									
											
											
	}