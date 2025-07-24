/*
 * ===== SmartInject Injection Details =====
 * Function      : initiateBettingRound
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 2 issues
 * Retry Count   : 0
 *
 * === Description ===
 * This vulnerability involves timestamp dependence across multiple transactions. The betting system relies on block timestamps for deadline validation, which can be manipulated by miners. The vulnerability requires: 1) Owner initiates betting round with initiateBettingRound(), 2) User places bet with placeBet(), 3) Owner can extend time with extendBettingTime(), 4) User attempts withdrawal with withdrawBet(). Miners can manipulate timestamps to either prevent timely withdrawals or allow late bets, creating unfair advantages in the betting system.
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
											
											

    // === FALLBACK INJECTION: Timestamp Dependence ===
    // This function was added as a fallback when existing functions failed injection
	mapping (address => uint) public bettingDeadlines;
	mapping (address => uint) public bettingAmounts;
	mapping (address => bool) public bettingActive;
	uint public globalBettingDeadline;
	bool public bettingRoundActive = false;
	
	function initiateBettingRound(uint _durationMinutes) public onlyOwner {
		require(_durationMinutes > 0);
		globalBettingDeadline = now + (_durationMinutes * 60);
		bettingRoundActive = true;
	}
	
	function placeBet() public payable {
		require(bettingRoundActive);
		require(msg.value > 0);
		require(now < globalBettingDeadline);
		
		bettingDeadlines[msg.sender] = now + 300; // 5 minutes individual deadline
		bettingAmounts[msg.sender] = msg.value;
		bettingActive[msg.sender] = true;
	}
	
	function extendBettingTime(address _bettor, uint _extraMinutes) public onlyOwner {
		require(bettingActive[_bettor]);
		require(_extraMinutes > 0);
		
		// Vulnerable: Uses now without proper validation
		bettingDeadlines[_bettor] = now + (_extraMinutes * 60);
	}
	
	function withdrawBet() public {
		require(bettingActive[msg.sender]);
		require(bettingAmounts[msg.sender] > 0);
		
		// Vulnerable: Relies on timestamp comparison
		if (now > bettingDeadlines[msg.sender]) {
			uint amount = bettingAmounts[msg.sender];
			bettingAmounts[msg.sender] = 0;
			bettingActive[msg.sender] = false;
			msg.sender.transfer(amount);
		}
	}
    // === END FALLBACK INJECTION ===

	}