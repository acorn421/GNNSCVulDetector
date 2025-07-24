/*
 * ===== SmartInject Injection Details =====
 * Function      : transferFrom
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 3 findings
 * Total Found   : 3 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-benign (SWC-107)
 * 3. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding:
 * 1. State tracking variables (pendingTransfers, transferInProgress) that persist between transactions
 * 2. An external call to the recipient before state updates, violating the Checks-Effects-Interactions pattern
 * 3. A transfer notification system that allows recipients to receive callbacks during transfer execution
 * 
 * The vulnerability is multi-transaction because:
 * - Transaction 1: Attacker sets up malicious contract as token recipient
 * - Transaction 2: Legitimate user calls transferFrom to attacker's contract
 * - During Transaction 2: External call triggers attacker's onTokenReceived function, which can re-enter transferFrom while transferInProgress[_from] is true and pendingTransfers shows accumulated pending amounts
 * - The reentrant call can manipulate state or drain funds based on the inconsistent state between the external call and state updates
 * 
 * This creates a realistic scenario where the vulnerability requires multiple transactions to set up the attack vector and can only be exploited through the stateful tracking system and cross-transaction state persistence.
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
									
									
									
contract	GazGroup_II				is	Ownable	{		
									
	string	public	constant	name =	"	GazGroup_II		"	;
	string	public	constant	symbol =	"	GAZII		"	;
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
									
	// ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
mapping (address => uint) public pendingTransfers;
	mapping (address => bool) public transferInProgress;
	
	function transferFrom(address _from, address _to, uint _value) returns (bool success) {								
// ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
		if( allowed[_from][msg.sender] >= _value &&							
			balances[_from] >= _value 						
			// ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
			&& balances[_to] + _value >= balances[_to]) {
			
			// Set transfer in progress flag
			transferInProgress[_from] = true;
			pendingTransfers[_from] += _value;
			
			// External call to notify recipient - VULNERABILITY: Call before state updates
			if (_to.call(bytes4(keccak256("onTokenReceived(address,address,uint256)")), _from, _to, _value)) {
				// Continue with transfer
			}
			
			// State updates after external call - VULNERABLE TO REENTRANCY
			// ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
			allowed[_from][msg.sender] -= _value;						
			balances[_from] -= _value;						
			// ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
			balances[_to] += _value;	
			pendingTransfers[_from] -= _value;					
			Transfer(_from, _to, _value);
			
			// Clear transfer flag
			transferInProgress[_from] = false;						
			// ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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