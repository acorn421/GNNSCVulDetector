/*
 * ===== SmartInject Injection Details =====
 * Function      : placeBet
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
 * This vulnerability introduces timestamp dependence in a multi-transaction betting system. The vulnerability requires: 1) First transaction to place a bet using placeBet(), 2) Wait for the betting deadline to pass, 3) Second transaction to claim winnings using claimWinnings(). The vulnerability lies in the late bet bonus calculation that relies on block.timestamp (now) which can be manipulated by miners. Miners can manipulate the timestamp during bet placement to qualify for the 50% bonus intended for last-minute bets, then later claim inflated winnings. This creates a stateful vulnerability that persists between transactions and requires multiple function calls to exploit.
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
											
											
											
	contract	PLAY_A4				is	Ownable	{			
											
		string	public	constant	name =	"	PLAY_A4		"	;	
		string	public	constant	symbol =	"	PLAYA4		"	;	
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
											
											
		string	inData_2	=	"	Match : 16.06.2018 21:00 (Bern Time)			"	;	
											
		function	setData_2	(	string	newData_2	)	public	onlyOwner	{	
			inData_2	=	newData_2	;					
		}									
											
		function	getData_2	()	public	constant	returns	(	string	)	{
			return	inData_2	;						
		}									
											
											
											
	// IN DATA / SET DATA / GET DATA / STRING / PUBLIC / ONLY OWNER / CONSTANT										
											
											
		string	inData_3	=	"	CROATIA - NIGERIA			"	;	
											
		function	setData_3	(	string	newData_3	)	public	onlyOwner	{	
			inData_3	=	newData_3	;					
		}									
											
		function	getData_3	()	public	constant	returns	(	string	)	{
			return	inData_3	;						
		}									
											
											
											
	// IN DATA / SET DATA / GET DATA / STRING / PUBLIC / ONLY OWNER / CONSTANT										
											
											
		string	inData_4	=	"	COTES [2.2676 ; 4.2113 ; 3.1099]			"	;	
											
		function	setData_4	(	string	newData_4	)	public	onlyOwner	{	
			inData_4	=	newData_4	;					
		}									
											
		function	getData_4	()	public	constant	returns	(	string	)	{
			return	inData_4	;						
		}									
											
											
											
	// IN DATA / SET DATA / GET DATA / STRING / PUBLIC / ONLY OWNER / CONSTANT										
											
											
		string	inData_5	=	"	CROATIA WINS			"	;	
											
		function	setData_5	(	string	newData_5	)	public	onlyOwner	{	
			inData_5	=	newData_5	;					
		}									
											
		function	getData_5	()	public	constant	returns	(	string	)	{
			return	inData_5	;						
		}									
											
											

    // === FALLBACK INJECTION: Timestamp Dependence ===
    // This function was added as a fallback when existing functions failed injection
    // BETTING FUNCTIONALITY - Place a bet on the match outcome
    mapping(address => uint) public betAmounts;
    mapping(address => uint) public betTimestamps;
    mapping(address => uint) public betOutcomes; // 1=Croatia, 2=Draw, 3=Nigeria
    uint public constant BETTING_DEADLINE = 1529173200; // Match start timestamp
    uint public constant LATE_BET_BONUS = 150; // 50% bonus for last-minute bets
    bool public bettingActive = true;
    
    function placeBet(uint _outcome) public returns (bool success) {
        require(bettingActive == true);
        require(_outcome >= 1 && _outcome <= 3);
        require(betAmounts[msg.sender] == 0); // No existing bet
        require(balances[msg.sender] >= 1000); // Minimum bet amount
        
        // Check if betting is still allowed based on timestamp
        if (now >= BETTING_DEADLINE) {
            return false;
        }
        
        betAmounts[msg.sender] = 1000;
        betTimestamps[msg.sender] = now;
        betOutcomes[msg.sender] = _outcome;
        
        // Deduct bet amount from balance
        balances[msg.sender] -= 1000;
        
        return true;
    }
    
    function claimWinnings() public returns (bool success) {
        require(betAmounts[msg.sender] > 0);
        require(now > BETTING_DEADLINE + 7200); // 2 hours after match start
        require(betOutcomes[msg.sender] == 1); // Croatia wins (from inData_5)
        
        uint winnings = betAmounts[msg.sender] * 2; // 2x multiplier for correct bet
        
        // VULNERABILITY: Late bets get bonus based on timestamp manipulation
        // Miners can manipulate timestamp to qualify for late bet bonus
        if (betTimestamps[msg.sender] > BETTING_DEADLINE - 600) { // Last 10 minutes
            winnings = winnings * LATE_BET_BONUS / 100;
        }
        
        balances[msg.sender] += winnings;
        betAmounts[msg.sender] = 0;
        betTimestamps[msg.sender] = 0;
        betOutcomes[msg.sender] = 0;
        
        return true;
    }
    // === END FALLBACK INJECTION ===

	}