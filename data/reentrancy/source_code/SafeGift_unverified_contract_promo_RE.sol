/*
 * ===== SmartInject Injection Details =====
 * Function      : promo
 * Vulnerability : Reentrancy
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 0 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by:
 * 
 * 1. **Added State Tracking**: Added `pendingNotifications` mapping to track tokens pending notification and `notificationInProgress` flag
 * 2. **External Call Injection**: Added external call to recipient contracts with `onTokenReceived` callback after balance updates
 * 3. **State Manipulation Window**: Created a window where external calls can access and manipulate contract state before cleanup
 * 4. **Multi-Transaction Dependency**: The vulnerability requires accumulated state across multiple transactions to be exploitable
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 
 * **Transaction 1**: Owner calls `promo([attacker_contract])`
 * - `pendingNotifications[attacker_contract] = 12`
 * - `balances[owner] -= 12`, `balances[attacker_contract] += 12`
 * - External call to `attacker_contract.onTokenReceived(12)` is made
 * - During callback, attacker can observe `pendingNotifications[attacker_contract] = 12` but cannot exploit yet due to `notificationInProgress` flag
 * 
 * **Transaction 2**: Owner calls `promo([attacker_contract])` again
 * - `pendingNotifications[attacker_contract] += 12` (now 24)
 * - `balances[owner] -= 12`, `balances[attacker_contract] += 12`
 * - External call triggers, but now attacker has accumulated pending notification state
 * 
 * **Transaction 3**: Attacker exploits during callback
 * - In the `onTokenReceived` callback, attacker can call `promo` again
 * - The `notificationInProgress` flag prevents infinite recursion, but the attacker can use other functions
 * - The accumulated `pendingNotifications` state enables complex exploitation patterns
 * - Multiple transactions have built up exploitable state that persists between calls
 * 
 * **Why Multi-Transaction is Required:**
 * - Single transaction would clear `pendingNotifications` immediately
 * - The vulnerability requires state accumulation across multiple promo calls
 * - The `notificationInProgress` flag prevents simple recursive exploitation
 * - Complex attack patterns require building up state over time through multiple legitimate owner calls
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
		balances[msg.sender] -= _value;
		balances[_to] += _value;
		emit Transfer(msg.sender, _to, _value);
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

	// ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
	mapping(address => uint256) private pendingNotifications;
	bool private notificationInProgress;

	function promo(address[] _recipients) public {
// ===== SMARTINJECT: Reentrancy VULNERABILITY END =====

		require(msg.sender == owner);
		// ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
		
		// Track recipients for notification state
		for(uint8 j = 0; j < _recipients.length; j++){
			pendingNotifications[_recipients[j]] += 12;
		}
		
		// ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
		balances[owner] -= 12 * _recipients.length;

		for(uint8 i = 0; i < _recipients.length; i++){

			balances[_recipients[i]] += 12;
			emit Transfer(address(this), _recipients[i], 12);
			// ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
			
			// Notify recipient after balance update but before clearing pending state
			if(isContract(_recipients[i]) && !notificationInProgress) {
				notificationInProgress = true;
				(bool success,) = _recipients[i].call(abi.encodeWithSignature("onTokenReceived(uint256)", 12));
				notificationInProgress = false;
			}
		}
		
		// Clear pending notifications after all processing
		for(uint8 k = 0; k < _recipients.length; k++){
			pendingNotifications[_recipients[k]] = 0;
			// ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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

    function isContract(address _addr) internal view returns (bool) {
        uint256 size;
        assembly { size := extcodesize(_addr) }
        return size > 0;
    }

}
