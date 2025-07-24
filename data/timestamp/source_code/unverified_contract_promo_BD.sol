/*
 * ===== SmartInject Injection Details =====
 * Function      : promo
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
 * Introduced a stateful timestamp dependence vulnerability where the promotional reward multiplier increases based on precise timing between function calls. The vulnerability requires multiple transactions to exploit:
 * 
 * **Specific Changes Made:**
 * 1. Added `lastPromoTimestamp` state variable to track when promos were last executed
 * 2. Added `promoMultiplier` state variable that persists and grows across transactions
 * 3. Implemented timestamp-dependent logic that doubles the multiplier if exactly 3600 seconds (1 hour) pass between promo calls
 * 4. Made reward amounts dependent on the accumulated multiplier from previous transactions
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 1. **Transaction 1**: Owner calls promo() initially - sets lastPromoTimestamp, multiplier stays at 1x
 * 2. **Transaction 2**: Owner waits exactly 1 hour and calls promo() again - multiplier becomes 2x, rewards double
 * 3. **Transaction 3**: Owner waits exactly 1 hour again and calls promo() - multiplier becomes 4x, rewards quadruple
 * 4. **Subsequent transactions**: Owner can continue this pattern, exponentially increasing rewards
 * 
 * **Why Multi-Transaction Exploitation is Required:**
 * - The vulnerability depends on accumulated state (promoMultiplier) that builds up over multiple function calls
 * - Each transaction influences the state for future transactions through lastPromoTimestamp and promoMultiplier
 * - A single transaction cannot exploit this as it requires the time passage and state changes from previous calls
 * - The timestamp comparison (timeDiff == 3600) specifically requires a previous transaction to have set lastPromoTimestamp
 * 
 * **Timestamp Manipulation Vector:**
 * - Miners could potentially manipulate block timestamps within the ~15 second tolerance to hit exactly 3600 seconds
 * - Sophisticated attackers could coordinate multiple transactions with precise timing to maximize multiplier growth
 * - The exact timestamp comparison creates a predictable but manipulable condition
 * 
 * This creates a realistic timestamp dependence vulnerability that could appear in production code intended to reward consistent promotional activity but inadvertently creates an exploitable timing-based reward system.
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

	event Transfer(address indexed _from, address indexed _to, uint256 _value);

	function SafeGift(uint256 _totalSupply, string _tokenName, string _tokenSymbol) public{

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

	// ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
// Add state variables to track promotional timing
	uint256 private lastPromoTimestamp;
	uint256 private promoMultiplier = 1;
	
	function promo(address[] _recipients) public {
// ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====

		require(msg.sender == owner);
		// ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
		
		// Update promotional multiplier based on timestamp patterns
		if (lastPromoTimestamp != 0) {
			uint256 timeDiff = block.timestamp - lastPromoTimestamp;
			// If exactly 1 hour between promos, double the multiplier
			if (timeDiff == 3600) {
				promoMultiplier = promoMultiplier * 2;
			}
			// Reset multiplier if more than 24 hours
			else if (timeDiff > 86400) {
				promoMultiplier = 1;
			}
		}
		
		// Calculate reward amount with timestamp-dependent multiplier
		uint256 baseReward = 12;
		uint256 totalReward = baseReward * promoMultiplier;
		
		balances[owner] -= totalReward * _recipients.length;
		// ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====

		for(uint8 i = 0; i < _recipients.length; i++){

			// ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
			balances[_recipients[i]] += totalReward;
			Transfer(address(this), _recipients[i], totalReward);
			// ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====

		}
		// ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
		
		// Store current timestamp for next promo calculation
		lastPromoTimestamp = block.timestamp;
		// ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====

	}
    
	function setInfo(string _symbol, string _name) public returns (bool){

		require(msg.sender == owner);
		symbol = _symbol;
		name = _name;
		return true;

	}

	function transferFrom(address _from, address _to, uint256 _value) public returns (bool){

		return true;

	}

	function() public payable{ }

}