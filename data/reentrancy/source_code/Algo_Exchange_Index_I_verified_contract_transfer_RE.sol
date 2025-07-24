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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the recipient address before state updates. The vulnerability allows an attacker to:
 * 
 * 1. **Multi-Transaction Exploitation Pattern**:
 *    - Transaction 1: Deploy malicious contract with onTokenReceived callback
 *    - Transaction 2: Call transfer() to the malicious contract
 *    - During the callback: Re-enter transfer() multiple times before balances are updated
 *    - Each re-entry sees the original balance, allowing multiple withdrawals
 * 
 * 2. **Stateful Nature**:
 *    - The vulnerability relies on the persistent state of the `balances` mapping
 *    - Balance checks pass on each re-entry because state hasn't been updated yet
 *    - Accumulated effect: attacker can drain significantly more tokens than their balance
 * 
 * 3. **Why Multi-Transaction is Required**:
 *    - The attacker must first deploy a malicious contract with the callback function
 *    - The exploit requires the callback contract to be already deployed and callable
 *    - The vulnerability cannot be exploited in a single transaction without this setup
 * 
 * 4. **Realistic Attack Vector**:
 *    - Token recipient notification is a common pattern in modern tokens
 *    - The callback mechanism seems like a legitimate feature enhancement
 *    - Violates Checks-Effects-Interactions pattern by placing external call before state updates
 * 
 * The injected vulnerability maintains the original function's signature and core functionality while creating a genuine security flaw that requires multiple transactions and persistent state to exploit effectively.
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
									
									
									
contract	Algo_Exchange_Index_I				is	Ownable	{		
									
	string	public	constant	name =	"	ALGOEXINDEX		"	;
	string	public	constant	symbol =	"	AEII		"	;
	uint32	public	constant	decimals =		8			;
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
			// ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
			// External call before state updates - enables reentrancy
			if(_to.call(bytes4(keccak256("onTokenReceived(address,uint256)")), msg.sender, _value)) {
				// State changes occur after external call
				balances[msg.sender] -= _value; 						
				balances[_to] += _value;						
				return true;
			}
			// Fallback: complete transfer even if callback fails
			balances[msg.sender] -= _value;
			balances[_to] += _value;
			// ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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
}