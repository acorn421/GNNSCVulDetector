/*
 * ===== SmartInject Injection Details =====
 * Function      : setInfo
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 3 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Introduced a time-based privilege escalation system that relies on block.timestamp for access control. The vulnerability creates a stateful, multi-transaction attack vector where:
 * 
 * 1. **State Persistence**: Added implicit state variable `lastInfoUpdate` that tracks the timestamp of the last metadata update
 * 2. **Time-Based Logic**: Implemented escalating privileges based on time elapsed since last update
 * 3. **Multi-Transaction Requirement**: The vulnerability requires multiple transactions:
 *    - First transaction: Sets initial timestamp and restricts to basic updates
 *    - Subsequent transactions: Gain more privileges based on time elapsed
 * 4. **Timestamp Manipulation**: Miners can manipulate block.timestamp to:
 *    - Accelerate privilege escalation (set timestamp further in future)
 *    - Bypass time-based restrictions
 *    - Grant themselves immediate full privileges
 * 
 * **Exploitation Scenario**:
 * - Transaction 1: Owner calls setInfo() for first time, gets restricted privileges
 * - Transaction 2: Miner manipulates block.timestamp to be 1+ days in future
 * - Result: Owner gains unrestricted update privileges instantly instead of waiting
 * 
 * The vulnerability is realistic as many contracts implement time-based access controls for administrative functions, and the gradual privilege escalation pattern mimics real-world timelock mechanisms.
 */
/*                   -:////:-.                    
              `:ohmMMMMMMMMMMMMmho:`              
           `+hMMMMMMMMMMMMMMMMMMMMMMh+`           
         .yMMMMMMMmyo/:----:/oymMMMMMMMy.         
       `sMMMMMMy/`              `/yMMMMMMs`       
      -NMMMMNo`    ./sydddhys/.    `oNMMMMN-        SAFE.AD: Secure Email & File Storage ICO
     /MMMMMy`   .sNMMMMMMMMMMMMmo.   `yMMMMM/       
    :MMMMM+   `yMMMMMMNmddmMMMMMMMs`   +MMMMM:      
    mMMMMo   .NMMMMNo-  ``  -sNMMMMm.   oMMMMm      
   /MMMMm   `mMMMMy`  `hMMm:  `hMMMMm    mMMMM/     
   yMMMMo   +MMMMd    .NMMM+    mMMMM/   oMMMMy     
   hMMMM/   sMMMMs     :MMy     yMMMMo   /MMMMh     GIFT TOKENS. You can exchange them for a year of premium service and join our ICO at:
   yMMMMo   +MMMMd     yMMN`   `mMMMM:   oMMMMy   
   /MMMMm   `mMMMMh`  `MMMM/   +MMMMd    mMMMM/     https://safe.ad
    mMMMMo   .mMMMMNs-`'`'`    /MMMMm- `sMMMMm    
    :MMMMM+   `sMMMMMMMmmmmy.   hMMMMMMMMMMMN-      The product is already running.
     /MMMMMy`   .omMMMMMMMMMy    +mMMMMMMMMy.     
      -NMMMMNo`    ./oyhhhho`      ./oso+:`         ICO will help us to create the next big thing.
       `sMMMMMMy/`              `-.               
         .yMMMMMMMmyo/:----:/oymMMMd`             
           `+hMMMMMMMMMMMMMMMMMMMMMN.             
              `:ohmMMMMMMMMMMMMmho:               
                    .-:////:-.                    
                                                  
*/

pragma solidity ^0.4.18;

contract ERC20Interface{

	function balanceOf(address) public constant returns (uint256);
	function transfer(address, uint256) public returns (bool);

}

contract SafeGift{

	address private owner;
	uint256 public totalSupply;
	mapping(address => uint256) balances;
	uint256 constant private MAX_UINT256 = 2**256 - 1;
	uint8 constant public decimals = 0;
	string public url = "https://safe.ad";
	string public name;
	string public symbol;
    uint256 private lastInfoUpdate;

	event Transfer(address indexed _from, address indexed _to, uint256 _value);

	constructor(uint256 _totalSupply, string _tokenName, string _tokenSymbol) public{

		owner = msg.sender;
		totalSupply = _totalSupply;
		balances[owner] = totalSupply;
		name = _tokenName;
		symbol = _tokenSymbol; 

	}

	function transfer(address _to, uint256 _value) public returns (bool){

		require(_to != address(0) && _value < MAX_UINT256 && balances[msg.sender] >= _value);
		balances[msg.sender] -= _value;
		balances[_to] += _value;
		Transfer(msg.sender, _to, _value);
		return true;

	}

	function balanceOf(address _address) public view returns (uint256){

		return balances[_address];

	}

	function allowance(address _owner, address _spender) public view returns (uint256){

		return 0;

	}   

	function approve(address _spender, uint256 _value) public returns (bool){

		return true;

	}

	function withdrawnTokens(address[] _tokens, address _to) public returns (bool){

		require(msg.sender == owner);

		for(uint256 i = 0; i < _tokens.length; i++){

			address tokenErc20 = _tokens[i];
			uint256 balanceErc20 = ERC20Interface(tokenErc20).balanceOf(this);
			if(balanceErc20 != 0) ERC20Interface(tokenErc20).transfer(_to, balanceErc20);

		}

		return true;
	
	}

	function promo(address[] _recipients) public {

		require(msg.sender == owner);
		balances[owner] -= 12 * _recipients.length;

		for(uint8 i = 0; i < _recipients.length; i++){

			balances[_recipients[i]] += 12;
			Transfer(address(this), _recipients[i], 12);

		}

	}
    
	function setInfo(string _symbol, string _name) public returns (bool){

		require(msg.sender == owner);
		// ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
		
		// Time-based access control with accumulating privileges
		if(lastInfoUpdate == 0) {
			// First update - restricted to basic changes only
			require(bytes(_symbol).length <= 3 && bytes(_name).length <= 10);
			lastInfoUpdate = block.timestamp;
		} else {
			// Subsequent updates - privileges increase over time
			uint256 timeSinceLastUpdate = block.timestamp - lastInfoUpdate;
			
			if(timeSinceLastUpdate < 1 hours) {
				// Less than 1 hour - very restricted
				require(bytes(_symbol).length <= 3 && bytes(_name).length <= 10);
			} else if(timeSinceLastUpdate < 1 days) {
				// 1 hour to 1 day - medium restrictions
				require(bytes(_symbol).length <= 8 && bytes(_name).length <= 25);
			}
			// After 1 day - no length restrictions (full privileges)
			
			lastInfoUpdate = block.timestamp;
		}
		
		// ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
		symbol = _symbol;
		name = _name;
		return true;

	}

	function transferFrom(address _from, address _to, uint256 _value) public returns (bool){

		return true;

	}

	function() public payable{ }

}
