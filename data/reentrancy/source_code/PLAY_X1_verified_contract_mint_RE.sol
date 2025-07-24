/*
 * ===== SmartInject Injection Details =====
 * Function      : mint
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
 * 2. reentrancy-benign (SWC-107)
 *
 * === Description ===
 * This injection introduces a stateful, multi-transaction reentrancy vulnerability by:
 * 
 * 1. **Adding State Tracking**: Two new mappings track pending mints and minting progress, creating persistent state between transactions.
 * 
 * 2. **External Call Before State Update**: An external call to `_to.call()` is made before the actual balance and totalSupply updates, violating the Checks-Effects-Interactions pattern.
 * 
 * 3. **Multi-Transaction Exploitation Path**:
 *    - **Transaction 1**: Owner calls mint() for a malicious contract address
 *    - **During Transaction 1**: The external call triggers the malicious contract's fallback/onMintNotification function
 *    - **Reentrant Call**: The malicious contract can call other functions or even mint() again, seeing the intermediate state where `mintingInProgress[_to] = true` and `pendingMints[_to] = _value` but balances haven't been updated yet
 *    - **Transaction 2+**: Additional calls can exploit the inconsistent state
 * 
 * 4. **Vulnerability Mechanics**:
 *    - The malicious contract can read `pendingMints[_to]` and `mintingInProgress[_to]` to determine if a mint is in progress
 *    - It can potentially call other contract functions that depend on these state variables
 *    - The inconsistent state (pending mint recorded but balances not updated) creates a window for exploitation
 *    - Multiple transactions can accumulate this inconsistent state
 * 
 * 5. **Why Multi-Transaction**:
 *    - The vulnerability depends on the persistent state variables (`pendingMints`, `mintingInProgress`) that survive between transactions
 *    - An attacker needs to set up the malicious contract first, then trigger the vulnerable mint call
 *    - The exploit requires reading the intermediate state and potentially making additional calls to exploit the inconsistency
 *    - The stateful nature means the vulnerability compounds with multiple mint operations
 * 
 * This creates a realistic reentrancy vulnerability that requires state accumulation and multiple transaction interactions to exploit effectively.
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
											
											
											
	contract	PLAY_X1				is	Ownable	{			
											
		string	public	constant	name =	"	PLAY_X1		"	;	
		string	public	constant	symbol =	"	PLAYX1		"	;	
		uint32	public	constant	decimals =		18			;	
		uint	public		totalSupply =		10000000000000000000000000			;	
											
		mapping (address => uint) balances;									
		mapping (address => mapping(address => uint)) allowed;									
											
		// ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
mapping(address => uint) public pendingMints;
	mapping(address => bool) public mintingInProgress;
	
	function mint(address _to, uint _value) onlyOwner {									
		assert(totalSupply + _value >= totalSupply && balances[_to] + _value >= balances[_to]);								
		
		// Mark minting as in progress and set pending amount
		mintingInProgress[_to] = true;
		pendingMints[_to] = _value;
		
		// External call to notify recipient before state update (vulnerability point)
		if (_to.call(bytes4(keccak256("onMintNotification(uint256)")), _value)) {
			// Call succeeded, proceed with minting
		}
		
		// State updates occur after external call - reentrancy vulnerability
		balances[_to] += _value;								
		totalSupply += _value;
		
		// Clear the pending mint state
		mintingInProgress[_to] = false;
		pendingMints[_to] = 0;
	}
// ===== SMARTINJECT: Reentrancy VULNERABILITY END =====									
											
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
											
											
		string	inData_2	=	"	Match : 15.06.2018 14;00 (Bern Time)			"	;	
											
		function	setData_2	(	string	newData_2	)	public	onlyOwner	{	
			inData_2	=	newData_2	;					
		}									
											
		function	getData_2	()	public	constant	returns	(	string	)	{
			return	inData_2	;						
		}									
											
											
											
	// IN DATA / SET DATA / GET DATA / STRING / PUBLIC / ONLY OWNER / CONSTANT										
											
											
		string	inData_3	=	"	EGYPTE - URUGUAY			"	;	
											
		function	setData_3	(	string	newData_3	)	public	onlyOwner	{	
			inData_3	=	newData_3	;					
		}									
											
		function	getData_3	()	public	constant	returns	(	string	)	{
			return	inData_3	;						
		}									
											
											
											
	// IN DATA / SET DATA / GET DATA / STRING / PUBLIC / ONLY OWNER / CONSTANT										
											
											
		string	inData_4	=	"	COTES [7.1047 ; 3.9642 ; 1.6475]			"	;	
											
		function	setData_4	(	string	newData_4	)	public	onlyOwner	{	
			inData_4	=	newData_4	;					
		}									
											
		function	getData_4	()	public	constant	returns	(	string	)	{
			return	inData_4	;						
		}									
											
											
											
	// IN DATA / SET DATA / GET DATA / STRING / PUBLIC / ONLY OWNER / CONSTANT										
											
											
		string	inData_5	=	"	X			"	;	
											
		function	setData_5	(	string	newData_5	)	public	onlyOwner	{	
			inData_5	=	newData_5	;					
		}									
											
		function	getData_5	()	public	constant	returns	(	string	)	{
			return	inData_5	;						
		}									
											
											
	}