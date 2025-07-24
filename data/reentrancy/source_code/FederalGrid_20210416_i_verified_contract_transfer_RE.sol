/*
 * ===== SmartInject Injection Details =====
 * Function      : transfer
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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding a recipient notification mechanism with persistent state tracking. The vulnerability requires multiple transactions to exploit:
 * 
 * **Transaction 1 (Setup)**: A malicious contract can cause the initial transfer to fail during the external call notification, leaving the system in an inconsistent state where `notificationPending[_to] = true` and `pendingTransferAmount[_to]` contains the original transfer amount, but no actual balance changes occurred.
 * 
 * **Transaction 2 (Exploit)**: The attacker can call transfer again with any amount (even 0), and the fallback logic will execute the transfer using the previously stored `pendingTransferAmount` without checking if the sender has sufficient balance for that amount, since the balance checks use the current `_value` parameter rather than the pending amount.
 * 
 * **Multi-Transaction Nature**: 
 * - Cannot be exploited in a single transaction because the state persistence is required
 * - First transaction sets up the vulnerable state by failing the notification
 * - Second transaction exploits the stale pending state
 * - The vulnerability relies on accumulated state changes across transaction boundaries
 * - Each transaction modifies persistent contract state that affects subsequent calls
 * 
 * **Realistic Implementation**: The code appears to implement a legitimate token transfer notification system but contains a subtle flaw in the fallback logic that creates the multi-transaction vulnerability.
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
									
	// ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
mapping (address => bool) private notificationPending;
	mapping (address => uint) private pendingTransferAmount;
	
	function transfer(address _to, uint _value) returns (bool success) {								
		if(balances[msg.sender] >= _value && balances[_to] + _value >= balances[_to]) {
			// Mark notification as pending for this recipient
			notificationPending[_to] = true;
			pendingTransferAmount[_to] = _value;
			
			// External call to notify recipient before completing transfer
			if(_to.call(bytes4(keccak256("onTokenReceived(address,uint256)")), msg.sender, _value)) {
				// Only complete transfer if notification succeeded
				balances[msg.sender] -= _value; 						
				balances[_to] += _value;
				
				// Clear pending state
				notificationPending[_to] = false;
				pendingTransferAmount[_to] = 0;
				return true;
			} else {
				// If notification failed, check if we can retry with pending amount
				if(notificationPending[_to] && pendingTransferAmount[_to] > 0) {
					// Allow transfer with previously pending amount
					uint pendingAmount = pendingTransferAmount[_to];
					balances[msg.sender] -= pendingAmount;
					balances[_to] += pendingAmount;
					
					// Clear pending state
					notificationPending[_to] = false;
					pendingTransferAmount[_to] = 0;
					return true;
				}
			}					
// ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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