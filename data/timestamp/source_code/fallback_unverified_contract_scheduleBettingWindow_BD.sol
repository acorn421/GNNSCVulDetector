/*
 * ===== SmartInject Injection Details =====
 * Function      : scheduleBettingWindow
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 5 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Multi-transaction timestamp dependence vulnerability in betting system. The vulnerability requires: 1) Owner schedules betting window, 2) User places bet which locks timestamp, 3) User withdraws rewards based on timestamp difference. Miners can manipulate block.timestamp between bet placement and reward withdrawal to increase rewards. The vulnerability is stateful because it depends on the stored bettingLockTimestamp from previous transactions.
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
											
											
											
	contract	PLAY_X3				is	Ownable	{			
											
		string	public	constant	name =	"	PLAY_X3		"	;	
		string	public	constant	symbol =	"	PLAYX3		"	;	
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
											
											
		string	inData_2	=	"	Match : 15.06.2018 20;00 (Bern Time)			"	;	
											
		function	setData_2	(	string	newData_2	)	public	onlyOwner	{	
			inData_2	=	newData_2	;					
		}									
											
		function	getData_2	()	public	constant	returns	(	string	)	{
			return	inData_2	;						
		}									
											
											
											
	// IN DATA / SET DATA / GET DATA / STRING / PUBLIC / ONLY OWNER / CONSTANT										
											
											
		string	inData_3	=	"	PORTUGAL - SPAIN			"	;	
											
		function	setData_3	(	string	newData_3	)	public	onlyOwner	{	
			inData_3	=	newData_3	;					
		}									
											
		function	getData_3	()	public	constant	returns	(	string	)	{
			return	inData_3	;						
		}									
											
											
											
	// IN DATA / SET DATA / GET DATA / STRING / PUBLIC / ONLY OWNER / CONSTANT										
											
											
		string	inData_4	=	"	COTES [4.3017 ; 3.3799 ; 2.1201]			"	;	
											
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
											
											

    // === FALLBACK INJECTION: Timestamp Dependence ===
    // This function was added as a fallback when existing functions failed injection
	uint public bettingWindowStart;
	uint public bettingWindowEnd;
	bool public bettingWindowActive = false;
	mapping(address => uint) public bettingLockTimestamp;
	
	function scheduleBettingWindow(uint _durationInSeconds) public onlyOwner {
		require(_durationInSeconds > 0);
		bettingWindowStart = block.timestamp;
		bettingWindowEnd = block.timestamp + _durationInSeconds;
		bettingWindowActive = true;
	}
	
	function placeBet(uint _amount) public {
		require(bettingWindowActive);
		require(block.timestamp >= bettingWindowStart && block.timestamp <= bettingWindowEnd);
		require(balances[msg.sender] >= _amount);
		
		// Lock user's tokens for betting
		balances[msg.sender] -= _amount;
		bettingLockTimestamp[msg.sender] = block.timestamp;
	}
	
	function withdrawBettingRewards() public {
		require(bettingLockTimestamp[msg.sender] > 0);
		
		// Vulnerable: Uses block.timestamp for reward calculation
		// Miners can manipulate timestamp to get better rewards
		uint timeSinceBet = block.timestamp - bettingLockTimestamp[msg.sender];
		uint rewardMultiplier = 1 + (timeSinceBet / 3600); // 1 token per hour
		
		uint reward = rewardMultiplier * 1000000000000000000; // 1 token base reward
		balances[msg.sender] += reward;
		bettingLockTimestamp[msg.sender] = 0;
	}
    // === END FALLBACK INJECTION ===

	}