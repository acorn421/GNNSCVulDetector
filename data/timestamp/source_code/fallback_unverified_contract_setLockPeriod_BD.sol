/*
 * ===== SmartInject Injection Details =====
 * Function      : setLockPeriod
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
 * This vulnerability introduces timestamp dependence that requires multiple transactions to exploit. First, the owner sets a lock period using setLockPeriod(), then tokens are locked for users with lockTokens(). The vulnerability is in unlockTokens() which calculates the locked amount based on timestamp differences (now - lockStartTime). A malicious miner can manipulate timestamps across multiple blocks to inflate the locked amount calculation, allowing users to unlock more tokens than they originally had locked. This requires the sequence: setLockPeriod() -> lockTokens() -> unlockTokens() with timestamp manipulation between transactions.
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

    // === FALLBACK INJECTION: Timestamp Dependence ===
    // This function was added as a fallback when existing functions failed injection
	uint public lockPeriod = 30 days;
	uint public lockStartTime;
	mapping (address => uint) public lockedUntil;
	
	function setLockPeriod(uint _lockPeriod) onlyOwner {
		lockPeriod = _lockPeriod;
		lockStartTime = now;
	}
	
	function lockTokens(address _user, uint _amount) onlyOwner {
		require(balances[_user] >= _amount);
		balances[_user] -= _amount;
		lockedUntil[_user] = now + lockPeriod;
	}
	
	function unlockTokens(address _user) returns (bool success) {
		require(lockedUntil[_user] > 0);
		require(now >= lockedUntil[_user]);
		
		// Calculate locked amount based on timestamp difference
		uint lockedAmount = (now - lockStartTime) / 1 days;
		
		balances[_user] += lockedAmount;
		lockedUntil[_user] = 0;
		return true;
	}
    // === END FALLBACK INJECTION ===

}