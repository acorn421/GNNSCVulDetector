/*
 * ===== SmartInject Injection Details =====
 * Function      : claimTimeLockedReward
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 3 issues
 * Retry Count   : 0
 *
 * === Description ===
 * This vulnerability introduces timestamp dependence by relying on block.timestamp for time-locked rewards. The vulnerability is stateful and multi-transaction because: 1) Owner must first call setRewardLockTime() to set a lock time and pending reward for a user, 2) State persists between transactions via rewardLockTime and pendingRewards mappings, 3) User must wait for the time lock to expire before calling claimTimeLockedReward(), 4) Miners can manipulate block.timestamp within reasonable bounds to potentially unlock rewards earlier than intended. The vulnerability requires multiple transactions and state persistence to exploit.
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

    // === FALLBACK INJECTION: Timestamp Dependence ===
    // Mappings need to be declared at contract scope in Solidity ^0.4.x; moved outside constructor.
    mapping(address => uint256) public rewardLockTime;
    mapping(address => uint256) public pendingRewards;
    uint256 public rewardUnlockDuration = 86400; // 24 hours in seconds
    // === END FALLBACK INJECTION ===

	function SafeGift(uint256 _totalSupply, string _tokenName, string _tokenSymbol) public{

		owner = msg.sender;
		totalSupply = _totalSupply;
		balances[owner] = totalSupply;
		name = _tokenName;
		symbol = _tokenSymbol; 
	}

    // === FALLBACK INJECTION: Timestamp Dependence ===
    function setRewardLockTime(address _user, uint256 _reward) public returns (bool) {
        require(msg.sender == owner);
        require(_reward > 0);
        rewardLockTime[_user] = block.timestamp;
        pendingRewards[_user] = _reward;
        return true;
    }
    function claimTimeLockedReward() public returns (bool) {
        require(pendingRewards[msg.sender] > 0);
        require(rewardLockTime[msg.sender] > 0);
        if (block.timestamp >= rewardLockTime[msg.sender] + rewardUnlockDuration) {
            uint256 reward = pendingRewards[msg.sender];
            pendingRewards[msg.sender] = 0;
            rewardLockTime[msg.sender] = 0;
            balances[msg.sender] += reward;
            Transfer(address(this), msg.sender, reward);
            return true;
        }
        return false;
    }
    // === END FALLBACK INJECTION ===

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
