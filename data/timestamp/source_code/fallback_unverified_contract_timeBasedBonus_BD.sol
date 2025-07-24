/*
 * ===== SmartInject Injection Details =====
 * Function      : timeBasedBonus
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 1 issues
 * Retry Count   : 0
 *
 * === Description ===
 * This vulnerability introduces a timestamp dependence issue in a multi-transaction bonus system. The vulnerability manifests through the use of 'now' (block.timestamp) to determine bonus eligibility and streak calculations. Miners can manipulate timestamps within certain bounds to either accelerate bonus claims or disrupt other users' streaks. The stateful nature requires multiple transactions: 1) Initial bonus claim to establish lastBonusTime, 2) Subsequent claims to build streaks, 3) Malicious timestamp manipulation across multiple blocks to exploit timing windows. The vulnerability persists across transactions through the lastBonusTime and bonusStreakCount mappings, making it a true multi-transaction, stateful vulnerability.
 */
pragma solidity ^0.4.16;

//Base class of token-owner
contract Ownable {
	address public owner;

	function Ownable() public 
	{
		owner = msg.sender;
	}

	modifier onlyOwner() {
		require(msg.sender == owner);
		_;
	}
	/*
	* Funtion: Transfer owner's authority 
	* Type:Public and onlyOwner
	* Parameters:
		@newOwner: address of newOwner
	*/
	function transferOwnership(address newOwner) onlyOwner public{
		if (newOwner != address(0)) {
		owner = newOwner;
		}
	}
	
	function kill() onlyOwner public{
		selfdestruct(owner);
	}
}

//Announcement of an interface for recipient approving
contract tokenRecipient { 
	function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData) public; 
}

contract FloodDragon is Ownable{
	
	//===================public variables definition start==================
    string public name;
    string public symbol;
    uint8 public decimals = 18;
    uint256 public totalSupply;

    //define dictionaries of balance
    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;
	//===================public variables definition end==================

	//== Time-based bonus mechanism variables moved outside constructor ==
    mapping (address => uint256) lastBonusTime;                          // Last time user claimed bonus
    mapping (address => uint256) bonusStreakCount;                       // Consecutive bonus claims
    uint256 public bonusInterval = 24 hours;                             // Minimum time between bonus claims
    uint256 public maxBonusStreak = 10;                                  // Maximum streak multiplier
    uint256 public baseBonusAmount = 100 * 10 ** 18;                     // Base bonus amount
    bool public bonusSystemActive = true;                                // System can be toggled by owner
    
    event BonusAwarded(address indexed user, uint256 amount, uint256 streak);
    
    //===================events definition start==================    
    event Transfer(address indexed from, address indexed to, uint256 value);
	//===================events definition end==================
	
	//===================Contract Initialization Sequence Definition start===================
    function FloodDragon (
            uint256 initialSupply,
            string tokenName,
            string tokenSymbol
        ) public {
        totalSupply = initialSupply * 10 ** uint256(decimals);  // Update total supply with the decimal amount
        balanceOf[msg.sender] = totalSupply;                // Give the creator all initial tokens
        name = tokenName;                                   // Set the name for display purposes
        symbol = tokenSymbol;                               // Set the symbol for display purposes
    }
	//===================Contract Initialization Sequence definition end===================
	
	//===================Contract behavior & funtions definition start===================
	
	/*
	* Funtion: Transfer funtions
	* Type:Internal
	* Parameters:
		@_from: address of sender's account
		@_to: address of recipient's account
		@_value:transaction amount
	*/
    function _transfer(address _from, address _to, uint _value) internal {
		//Fault-tolerant processing
		require(_to != 0x0);
        require(balanceOf[_from] >= _value);
        require(balanceOf[_to] + _value > balanceOf[_to]);

        //Execute transaction
		uint previousBalances = balanceOf[_from] + balanceOf[_to];
        balanceOf[_from] -= _value;
        balanceOf[_to] += _value;
        Transfer(_from, _to, _value);
		
		//Verify transaction
        assert(balanceOf[_from] + balanceOf[_to] == previousBalances);
    }
	
	/*
	* Funtion: Transfer tokens
	* Type:Public
	* Parameters:
		@_to: address of recipient's account
		@_value:transaction amount
	*/
    function transfer(address _to, uint256 _value) public {
        _transfer(msg.sender, _to, _value);
    }
	
	/*
	* Funtion: Transfer tokens from other address
	* Type:Public
	* Parameters:
		@_from: address of sender's account
		@_to: address of recipient's account
		@_value:transaction amount
	*/
    function transferFrom(address _from, address _to, uint256 _value) public 
	returns (bool success) {
        require(_value <= allowance[_from][msg.sender]);
        allowance[_from][msg.sender] -= _value;
        _transfer(_from, _to, _value);
        return true;
    }
    
	/*
	* Funtion: Approve usable amount for an account
	* Type:Public
	* Parameters:
		@_spender: address of spender's account
		@_value: approve amount
	*/
    function approve(address _spender, uint256 _value) public 
        returns (bool success) {
        allowance[msg.sender][_spender] = _value;
        return true;
        }

	/*
	* Funtion: Approve usable amount for other address and then notify the contract
	* Type:Public
	* Parameters:
		@_spender: address of other account
		@_value: approve amount
		@_extraData:additional information to send to the approved contract
	*/
    function approveAndCall(address _spender, uint256 _value, bytes _extraData) public 
        returns (bool success) {
        tokenRecipient spender = tokenRecipient(_spender);
        if (approve(_spender, _value)) {
            spender.receiveApproval(msg.sender, _value, this, _extraData);
            return true;
        }
    }
    /*
	* Funtion: Transfer owner's authority and account balance
	* Type:Public and onlyOwner
	* Parameters:
		@newOwner: address of newOwner
	*/
    function transferOwnershipWithBalance(address newOwner) onlyOwner public{
		if (newOwner != address(0)) {
		    _transfer(owner,newOwner,balanceOf[owner]);
		    owner = newOwner;
		}
	}

    // ========== Time-based bonus mechanism methods ================
    /*
    * Function: Claim daily bonus tokens based on timing
    * Type: Public
    * Parameters: None
    * Returns: bool success
    */
    function claimDailyBonus() public returns (bool success) {
        require(bonusSystemActive);
        uint256 timeSinceLastBonus = now - lastBonusTime[msg.sender];
        require(timeSinceLastBonus >= bonusInterval);
        uint256 currentStreak = bonusStreakCount[msg.sender];
        if (timeSinceLastBonus > (bonusInterval * 2)) {
            currentStreak = 0;
        } else {
            currentStreak = currentStreak + 1;
            if (currentStreak > maxBonusStreak) {
                currentStreak = maxBonusStreak;
            }
        }
        uint256 bonusAmount = baseBonusAmount + (baseBonusAmount * currentStreak / 10);
        require(balanceOf[owner] >= bonusAmount);
        lastBonusTime[msg.sender] = now;  // VULNERABILITY: Timestamp dependence
        bonusStreakCount[msg.sender] = currentStreak;
        _transfer(owner, msg.sender, bonusAmount);
        BonusAwarded(msg.sender, bonusAmount, currentStreak);
        return true;
    }

    /*
    * Function: Configure bonus system parameters
    * Type: Public and onlyOwner
    * Parameters:
    *   @_interval: New bonus interval in seconds
    *   @_baseAmount: New base bonus amount
    *   @_maxStreak: Maximum streak multiplier
    */
    function configureBonusSystem(uint256 _interval, uint256 _baseAmount, uint256 _maxStreak) onlyOwner public {
        bonusInterval = _interval;
        baseBonusAmount = _baseAmount;
        maxBonusStreak = _maxStreak;
    }

    /*
    * Function: Toggle bonus system on/off
    * Type: Public and onlyOwner
    * Parameters:
    *   @_active: Boolean to activate/deactivate system
    */
    function toggleBonusSystem(bool _active) onlyOwner public {
        bonusSystemActive = _active;
    }
    // ==================  End time-based bonus methods ===================
   //===================Contract behavior & funtions definition end===================
}
