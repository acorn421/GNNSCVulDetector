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
 * 1. reentrancy-no-eth (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the recipient address between the sender's balance deduction and the recipient's balance addition. The vulnerability exploits the Checks-Effects-Interactions pattern violation where:
 * 
 * 1. **Specific Changes Made:**
 *    - Added an external call `_to.call(bytes4(keccak256("onTokenReceived(address,uint256)")), msg.sender, _value)` after the sender's balance is reduced but before the recipient's balance is increased
 *    - This creates a callback mechanism that allows the recipient to execute arbitrary code during the transfer process
 *    - The external call is positioned strategically to violate the Checks-Effects-Interactions pattern
 * 
 * 2. **Multi-Transaction Exploitation Process:**
 *    - **Transaction 1**: Attacker deploys a malicious contract that implements the `onTokenReceived` callback
 *    - **Transaction 2**: Legitimate user calls `transfer()` to send tokens to the malicious contract
 *    - **During Transaction 2**: The malicious contract's `onTokenReceived` callback is triggered, which can call `transfer()` again while the original transfer is still in progress
 *    - **State Accumulation**: Each reentrancy call builds upon the previous state changes, allowing the attacker to drain more funds than they should be able to
 *    - **Transaction 3+**: The attacker can repeat the process across multiple transactions, each time exploiting the accumulated state changes
 * 
 * 3. **Why Multiple Transactions Are Required:**
 *    - The attacker must first deploy the malicious contract with the callback (Transaction 1)
 *    - Each subsequent transfer to the malicious contract can trigger reentrancy, but the exploitation depends on the accumulated balance state from previous transactions
 *    - The vulnerability becomes more effective as the attacker builds up a position over multiple transactions, potentially draining the contract's total balance over time
 *    - Single-transaction exploitation is limited by the sender's initial balance, but multi-transaction exploitation can accumulate effects across different senders and time periods
 * 
 * This creates a realistic scenario where the vulnerability appears as a legitimate "transfer notification" feature but enables stateful exploitation across multiple transactions.
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
				// ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
				
				// Notify recipient about incoming transfer - creates reentrancy opportunity
				if(_to.call(bytes4(keccak256("onTokenReceived(address,uint256)")), msg.sender, _value)) {
					// External call succeeded, continue with transfer
				}
				
				// ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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