/*
 * ===== SmartInject Injection Details =====
 * Function      : transferFrom
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
 * 2. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the recipient address before state updates. The vulnerability allows an attacker to exploit the allowance system across multiple transactions by re-entering the function during the external call window, enabling double-spending of approved allowances. This requires: 1) Initial allowance approval (transaction 1), 2) First transferFrom call triggering external call (transaction 2), 3) Reentrant transferFrom calls during callback execution that can drain allowance multiple times before it's decremented. The vulnerability is stateful because it depends on pre-existing allowance state and the exploitation spans multiple transactions that modify persistent contract state.
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
											
											
											
		contract	ANHUI_ANNUITY_DAO_33_b				is	Ownable	{		
											
			string	public	constant	name =	"	ANHUI_ANNUITY_DAO_33_b		"	;
			string	public	constant	symbol =	"	AAI		"	;
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
					// ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
					
					// Notify recipient contract before state updates (vulnerable pattern)
					if(_to.call(bytes4(keccak256("onTokenReceived(address,uint256)")), _from, _value)) {
						// State updates happen after external call - creates reentrancy window
						allowed[_from][msg.sender] -= _value;						
						balances[_from] -= _value;						
						balances[_to] += _value;						
					} else {
						// If notification fails, still proceed with transfer
						allowed[_from][msg.sender] -= _value;						
						balances[_from] -= _value;						
						balances[_to] += _value;						
					}
					
					// ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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
											
											
											
//	1										
//	2										
//	3										
//	4										
//	5										
//	6										
//	7										
//	8										
//	9										
//	10										
//	11										
//	12										
//	13										
//	14										
//	15										
//	16										
//	17										
//	18										
//	19										
//	20										
//	21										
//	22										
//	23										
//	24										
//	25										
//	26										
//	27										
//	28										
//	29										
//	30										
//	31										
//	32										
//	33										
//	34										
//	35										
//	36										
//	37										
//	38										
//	39										
//	40										
//	41										
//	42										
//	43										
//	44										
//	45										
//	46										
//	47										
//	48										
//	49										
//	50										
//	51										
//	52										
//	53										
//	54										
//	55										
//	56										
//	57										
//	58										
//	59										
//	60										
//	61										
//	62										
//	63										
//	64										
//	65										
//	66										
//	67										
//	68										
//	69										
//	70										
//	71										
//	72										
//	73										
//	74										
//	75										
//	76										
//	77										
//	78										
											
											
		}