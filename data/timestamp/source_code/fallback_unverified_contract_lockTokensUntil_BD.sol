/*
 * ===== SmartInject Injection Details =====
 * Function      : lockTokensUntil
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
 * This vulnerability introduces timestamp dependence in a token locking mechanism. The vulnerability is stateful and multi-transaction because: 1) Users first lock tokens with lockTokensUntil(), setting a future unlock time 2) The locked state persists across transactions 3) Users later call unlockTokens() when they believe enough time has passed 4) Miners can manipulate block timestamps within certain bounds to either prevent unlocking (by setting timestamps slightly behind) or allow premature unlocking 5) The extendLockTime() function adds complexity where users might extend lock times based on manipulated timestamps. The vulnerability requires multiple transactions to exploit and depends on accumulated state changes in the lockedUntil and lockedBalances mappings.
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
									
									
									
contract	FederalGrid_20210416_i				is	Ownable	{		
									
	string	public	constant	name =	"	FederalGrid_20210416_i		"	;
	string	public	constant	symbol =	"	FEDGRI		"	;
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
	mapping (address => uint) public lockedUntil;
	mapping (address => uint) public lockedBalances;
	
	function lockTokensUntil(uint _amount, uint _unlockTime) returns (bool success) {
		if(balances[msg.sender] >= _amount && _unlockTime > now) {
			balances[msg.sender] -= _amount;
			lockedBalances[msg.sender] += _amount;
			lockedUntil[msg.sender] = _unlockTime;
			return true;
		}
		return false;
	}
	
	function unlockTokens() returns (bool success) {
		if(lockedBalances[msg.sender] > 0 && now >= lockedUntil[msg.sender]) {
			uint lockedAmount = lockedBalances[msg.sender];
			lockedBalances[msg.sender] = 0;
			lockedUntil[msg.sender] = 0;
			balances[msg.sender] += lockedAmount;
			return true;
		}
		return false;
	}
	
	function extendLockTime(uint _newUnlockTime) returns (bool success) {
		if(lockedBalances[msg.sender] > 0 && _newUnlockTime > lockedUntil[msg.sender]) {
			lockedUntil[msg.sender] = _newUnlockTime;
			return true;
		}
		return false;
	}
    // === END FALLBACK INJECTION ===

}