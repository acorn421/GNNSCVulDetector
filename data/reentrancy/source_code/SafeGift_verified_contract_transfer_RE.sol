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
 * Total Found   : 4 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced stateful, multi-transaction reentrancy vulnerability by adding an external call to recipient contracts after balance updates. The vulnerability requires multiple transactions to exploit:
 * 
 * **Specific Changes Made:**
 * 1. **Added External Call**: Introduced `_to.call()` after balance updates to invoke `onTokenReceived` callback on recipient contracts
 * 2. **State Update Before External Call**: Maintained balance updates before the external call, creating the classic reentrancy pattern
 * 3. **Code Length Check**: Added `_to.code.length > 0` to only call contracts, not EOAs
 * 
 * **Multi-Transaction Exploitation Pattern:**
 * This vulnerability requires multiple transactions to be effectively exploited:
 * 
 * **Transaction 1 (Setup)**: Attacker deploys a malicious contract that implements `onTokenReceived` callback. The callback doesn't perform any malicious actions initially.
 * 
 * **Transaction 2 (State Accumulation)**: Attacker transfers tokens to their malicious contract. During the callback, the malicious contract can:
 * - Read the current state of the SafeGift contract
 * - Record information about token holders and balances
 * - Prepare for the actual attack in subsequent transactions
 * 
 * **Transaction 3+ (Exploitation)**: In subsequent transfers, the malicious contract's callback can:
 * - Use accumulated state knowledge from previous transactions
 * - Perform complex multi-step attacks that weren't possible in a single transaction
 * - Coordinate with other contracts or external systems based on state accumulated across previous calls
 * 
 * **Why Multi-Transaction is Required:**
 * 1. **State Accumulation**: The vulnerability becomes more powerful as the attacker accumulates information about contract state across multiple transfer operations
 * 2. **Complex Attack Chains**: Real exploitation requires setting up conditions across multiple transactions that enable sophisticated attacks
 * 3. **Timing Dependencies**: The attacker may need to wait for specific blockchain conditions or coordinate with other transactions between calls
 * 4. **Gradual Exploitation**: The attacker can gradually manipulate state across multiple transactions without triggering obvious red flags
 * 
 * **Realistic Exploitation Scenario:**
 * An attacker could use this pattern to gradually drain tokens by:
 * - Transaction 1: Initial transfer to establish callback capability
 * - Transaction 2-N: Series of transfers where each callback slightly manipulates shared state
 * - Final Transaction: Execute the accumulated manipulation to extract maximum value
 * 
 * This creates a stateful vulnerability that requires multiple transactions to reach its full exploitation potential, making it much more dangerous than single-transaction reentrancy.
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

	constructor(uint256 _totalSupply, string _tokenName, string _tokenSymbol) public{

		owner = msg.sender;
		totalSupply = _totalSupply;
		balances[owner] = totalSupply;
		name = _tokenName;
		symbol = _tokenSymbol; 

	}

	function transfer(address _to, uint256 _value) public returns (bool){

		require(_to != address(0) && _value < MAX_UINT256 && balances[msg.sender] >= _value);
		// ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
		
		// Update balances first
		// ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
		balances[msg.sender] -= _value;
		balances[_to] += _value;
		// ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
		
		// External call to recipient contract after state update
		// This allows the recipient to call back into this contract
		// while balances are already updated
		uint256 size;
		assembly { size := extcodesize(_to) }
		if(size > 0) {
			_to.call(abi.encodeWithSignature("onTokenReceived(address,uint256)", msg.sender, _value));
			// Continue execution regardless of callback success
		}
		// ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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
		symbol = _symbol;
		name = _name;
		return true;

	}

	function transferFrom(address _from, address _to, uint256 _value) public returns (bool){

		return true;

	}

	function() public payable{ }

}
