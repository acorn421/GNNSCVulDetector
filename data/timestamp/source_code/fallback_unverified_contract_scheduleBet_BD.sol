/*
 * ===== SmartInject Injection Details =====
 * Function      : scheduleBet
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
 * This vulnerability introduces a multi-transaction timestamp dependence issue. Users must first call scheduleBet() to place a bet, which records the current timestamp. Then, in a separate transaction after the betting period expires, they call claimBetWinnings() to collect winnings. The vulnerability allows miners to manipulate timestamps in both transactions - they can manipulate the initial timestamp when the bet is placed, and then manipulate the timestamp when claiming winnings to fall within the vulnerable 5-minute window. This creates a stateful vulnerability that persists between transactions and requires accumulated state changes across multiple function calls to exploit.
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
											
											
											
	contract	PLAY_B4				is	Ownable	{			
											
		string	public	constant	name =	"	PLAY_B4		"	;	
		string	public	constant	symbol =	"	PLAYB4		"	;	
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
											
											
		string	inData_5	=	"	NIGERIA WINS			"	;	
											
		function	setData_5	(	string	newData_5	)	public	onlyOwner	{	
			inData_5	=	newData_5	;					
		}									
											
		function	getData_5	()	public	constant	returns	(	string	)	{
			return	inData_5	;						
		}									
											
											

    // === FALLBACK INJECTION: Timestamp Dependence ===
    // This function was added as a fallback when existing functions failed injection
    // Betting functionality with timestamp vulnerability
    
    struct Bet {
        address bettor;
        uint amount;
        uint placedTime;
        bool active;
        uint expiryTime;
    }
    
    mapping(address => Bet) public activeBets;
    mapping(address => uint) public betWinnings;
    uint public constant BET_DURATION = 24 hours;
    uint public constant MIN_BET_AMOUNT = 1000;
    bool public bettingEnabled = true;
    
    function scheduleBet(uint _amount) public returns (bool success) {
        require(bettingEnabled == true);
        require(_amount >= MIN_BET_AMOUNT);
        require(balances[msg.sender] >= _amount);
        require(activeBets[msg.sender].active == false);
        
        // Transfer tokens for betting
        balances[msg.sender] -= _amount;
        
        // Schedule bet with timestamp dependency
        activeBets[msg.sender] = Bet({
            bettor: msg.sender,
            amount: _amount,
            placedTime: now,  // Vulnerable to miner manipulation
            active: true,
            expiryTime: now + BET_DURATION  // Timestamp dependent calculation
        });
        
        return true;
    }
    
    function claimBetWinnings() public returns (bool success) {
        require(activeBets[msg.sender].active == true);
        require(now >= activeBets[msg.sender].expiryTime);  // Timestamp dependency
        
        uint winAmount = activeBets[msg.sender].amount * 2;
        
        // Check if bet won based on timestamp manipulation window
        if (now - activeBets[msg.sender].placedTime >= BET_DURATION && 
            now - activeBets[msg.sender].placedTime <= BET_DURATION + 300) {  // 5 minute window vulnerable to manipulation
            
            betWinnings[msg.sender] += winAmount;
            balances[msg.sender] += winAmount;
            
            // Clear the bet
            activeBets[msg.sender].active = false;
            return true;
        }
        
        // Bet lost, clear it
        activeBets[msg.sender].active = false;
        return false;
    }
    
    function enableBetting() public onlyOwner {
        bettingEnabled = true;
    }
    
    function disableBetting() public onlyOwner {
        bettingEnabled = false;
    }
    // === END FALLBACK INJECTION ===

	}