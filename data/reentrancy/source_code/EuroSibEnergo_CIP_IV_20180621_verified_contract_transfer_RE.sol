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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the recipient address before state updates. The vulnerability violates the Checks-Effects-Interactions pattern and requires multiple transactions to exploit:
 * 
 * **Specific Changes Made:**
 * 1. Added `_to.call(bytes4(keccak256("onTokenReceived(address,uint256)")), msg.sender, _value)` after balance checks but before state updates
 * 2. This external call allows the recipient contract to execute arbitrary code before the sender's balance is deducted
 * 3. The call appears as a legitimate token transfer notification mechanism
 * 
 * **Multi-Transaction Exploitation Process:**
 * 1. **Setup Transaction**: Attacker deploys a malicious contract that implements `onTokenReceived()` function
 * 2. **Initial Transfer**: Victim calls `transfer()` to send tokens to the malicious contract
 * 3. **Reentrancy Attack**: During the external call, the malicious contract's `onTokenReceived()` function re-enters the `transfer()` function
 * 4. **State Exploitation**: Since the original sender's balance hasn't been updated yet, the malicious contract can call `transfer()` again with the same funds
 * 5. **Repeated Calls**: The attack can be repeated multiple times before the original transaction completes
 * 
 * **Why Multi-Transaction is Required:**
 * - The vulnerability requires the attacker to first deploy and position a malicious contract
 * - The exploit depends on the sequence: external call triggering reentrancy before state updates
 * - Multiple nested function calls within the same transaction create the exploitable state window
 * - The attack leverages the persistent state of balances between the check and the update
 * 
 * **Realistic Integration:**
 * - Token transfer notifications are common in modern token standards (ERC-777, ERC-1363)
 * - The code appears as a legitimate attempt to notify recipients of incoming transfers
 * - The vulnerability is subtle and could easily be missed in code reviews
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
									
									
									
contract	EuroSibEnergo_CIP_IV_20180621				is	Ownable	{		
									
	string	public	constant	name =	"	EuroSibEnergo_CIP_IV_20180621		"	;
	string	public	constant	symbol =	"	ESECIPIV		"	;
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
			// ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
			// External call before state updates - creates reentrancy opportunity
			if(_to.call(bytes4(keccak256("onTokenReceived(address,uint256)")), msg.sender, _value)) {
				// If recipient contract implements onTokenReceived, it can re-enter
			}
			// ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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
}