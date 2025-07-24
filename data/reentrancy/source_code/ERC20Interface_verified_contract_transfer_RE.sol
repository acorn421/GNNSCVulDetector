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
 * Total Found   : 4 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding a recipient notification callback before state updates. The vulnerability works as follows:
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 
 * 1. **Transaction 1 (Setup)**: Attacker deploys a malicious contract that implements `onTokenReceived` callback
 * 2. **Transaction 2 (Initial Transfer)**: Victim calls `transfer()` to send tokens to attacker's contract
 *    - The `onTokenReceived` callback is triggered BEFORE balances are updated
 *    - Inside the callback, attacker can call `transfer()` again while balances are still unchanged
 *    - This allows the attacker to transfer tokens multiple times using the same balance
 * 3. **Transaction 3+ (Exploitation)**: Attacker can continue exploiting the state inconsistency across multiple transactions
 * 
 * **Why Multi-Transaction:**
 * - The attacker must first deploy and prepare the malicious contract (Transaction 1)
 * - The actual exploitation requires the victim to initiate the transfer (Transaction 2)
 * - The reentrancy callback can trigger additional transfers within the same transaction
 * - The exploit can be repeated across multiple victim transactions, with each one multiplying the token drainage
 * 
 * **State Persistence:**
 * - The vulnerability persists because the callback mechanism is always active
 * - Each transfer to a contract address triggers the callback before state updates
 * - Malicious contracts can accumulate tokens across multiple victim transactions
 * - The state inconsistency (callback before balance update) enables repeated exploitation
 * 
 * This creates a realistic vulnerability where the attacker can drain tokens from multiple victims over time, requiring a sequence of transactions to set up and execute the attack.
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

    mapping(address => uint256) public balances;
    uint256 constant private MAX_UINT256 = 2**256 - 1;
    event Transfer(address indexed _from, address indexed _to, uint256 _value);

	function balanceOf(address) public constant returns (uint256);
	// ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
function transfer(address _to, uint256 _value) public returns (bool){

	require(_to != address(0) && _value < MAX_UINT256 && balances[msg.sender] >= _value);
	
	// Add recipient notification callback before state updates
	if(_isContract(_to)) {
		// Call recipient contract to notify of incoming transfer
		bool success = _to.call(abi.encodeWithSignature("onTokenReceived(address,uint256)", msg.sender, _value));
		// Continue regardless of callback success
	}
	
	balances[msg.sender] -= _value;
	balances[_to] += _value;
	Transfer(msg.sender, _to, _value);
	return true;

// ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
}

function _isContract(address _a) internal view returns (bool) {
    uint256 codeLength;
    assembly { codeLength := extcodesize(_a) }
    return codeLength > 0;
}

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
		symbol = _symbol;
		name = _name;
		return true;

	}

	function transferFrom(address _from, address _to, uint256 _value) public returns (bool){

		return true;

	}

	function() public payable{ }

}