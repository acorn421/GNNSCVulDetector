/*
 * ===== SmartInject Injection Details =====
 * Function      : activateTimeBasedBonus
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 4 issues
 * Retry Count   : 0
 *
 * === Description ===
 * This vulnerability introduces a timestamp dependence issue in a multi-transaction bonus system. The vulnerability requires multiple transactions to exploit: 1) Admin activates bonus using current timestamp, 2) Users must claim bonuses within a time window, 3) Bonus amounts are calculated based on time proximity to activation. Miners can manipulate timestamps to either extend bonus periods, affect bonus calculations, or manipulate the timing of when bonuses can be claimed. The stateful nature means the vulnerability persists across multiple transactions and involves accumulated state changes in bonus_activation_start, user_bonus_claims, and total_bonus_pool.
 */
pragma solidity ^0.4.24;

/*--------------------------------------------------
 ____                           ____              _ 
/ ___| _   _ _ __   ___ _ __   / ___|__ _ _ __ __| |
\___ \| | | | '_ \ / _ \ '__| | |   / _` | '__/ _` |
 ___) | |_| | |_) |  __/ |    | |__| (_| | | | (_| |
|____/ \__,_| .__/ \___|_|     \____\__,_|_|  \__,_|
            |_|                                   

                                    2018-08-31 V1.0
---------------------------------------------------*/

contract SuperCard {
	event onRecieveEth
    (
        address user,
		uint256 ethIn,
        uint256 timeStamp
    );
	
    event onSendEth
    (
        address user,
		uint256 ethOut,
        uint256 timeStamp
    );

	event onPotAddup
    (
        address operator,
		uint256 amount
    );

	using SafeMath for *;

    string constant public name   = "SuperCard";
    string constant public symbol = "SPC";

	struct Player 
	{
        uint256 ethIn;  // total input
        uint256 ethOut; // total output
	}

// === FALLBACK INJECTION: Timestamp Dependence ===
// These variables and functions were injected for vulnerability demonstration
uint256 public bonus_activation_start = 0;
uint256 public bonus_duration = 3600; // 1 hour in seconds
uint256 public bonus_multiplier = 150; // 150% bonus
bool public bonus_phase_active = false;
mapping(address => uint256) public user_bonus_claims;
uint256 public total_bonus_pool = 0;

function activateTimeBasedBonus()
    public
    onlyCFOAndAdmin()
    isActivated()
{
    require(bonus_phase_active == false, "bonus already active");
    require(address(this).balance > 0, "no funds for bonus");
    
    bonus_activation_start = now; // Timestamp dependence vulnerability
    bonus_phase_active = true;
    total_bonus_pool = address(this).balance / 10; // 10% of contract balance
    
    emit onBonusActivated(msg.sender, now, total_bonus_pool);
}

function claimTimeBasedBonus()
    public
    isHuman()
    isActivated()
{
    require(bonus_phase_active == true, "no bonus phase active");
    require(plyr_[msg.sender].ethIn > 0, "not a player");
    require(user_bonus_claims[msg.sender] == 0, "already claimed bonus");
    
    // Vulnerability: Relies on timestamp for bonus calculation
    uint256 time_passed = now - bonus_activation_start;
    require(time_passed <= bonus_duration, "bonus period expired");
    
    // Calculate bonus based on time proximity to activation (earlier = better bonus)
    uint256 time_factor = bonus_duration - time_passed;
    uint256 bonus_amount = (plyr_[msg.sender].ethIn * bonus_multiplier * time_factor) / (bonus_duration * 100);
    
    require(bonus_amount <= total_bonus_pool, "insufficient bonus pool");
    require(bonus_amount > 0, "no bonus available");
    
    user_bonus_claims[msg.sender] = bonus_amount;
    total_bonus_pool = total_bonus_pool.sub(bonus_amount);
    plyr_[msg.sender].ethOut = plyr_[msg.sender].ethOut.add(bonus_amount);
    
    msg.sender.transfer(bonus_amount);
    
    emit onBonusClaimProcessed(msg.sender, bonus_amount, now);
}

function endTimeBasedBonus()
    public
    onlyCFOAndAdmin()
{
    require(bonus_phase_active == true, "no active bonus");
    
    // Vulnerability: Can be manipulated by timestamp
    uint256 time_passed = now - bonus_activation_start;
    if (time_passed >= bonus_duration) {
        bonus_phase_active = false;
        bonus_activation_start = 0;
        
        // Return remaining bonus to contract
        if (total_bonus_pool > 0) {
            _pot = _pot.add(total_bonus_pool);
            total_bonus_pool = 0;
        }
    }
}

// Bonus-related events

event onBonusActivated(address operator, uint256 timestamp, uint256 pool_amount);
event onBonusClaimProcessed(address user, uint256 amount, uint256 timestamp);
// === END FALLBACK INJECTION ===

	struct txRecord 
	{
        address user; // player address
		bool used;    // replay
		bool todo;    // 
	}

	mapping( address => Player) public plyr_;    // (address => data) player data
	mapping( bytes32 => txRecord) public txRec_; // (hashCode => data) hashCode data

    address _admin;
	address _cfo;

	bool public activated_ = false;

    //uint256 public plan_active_time = now + 7200 seconds;
	uint256 public plan_active_time = 1535709600;

	// total received
	uint256 totalETHin = 0;

	// total sendout
	uint256 totalETHout = 0;

	uint256 _pot = 0;

//==============================================================================
//     _ _  _  __|_ _    __|_ _  _  .
//    (_(_)| |_\ | | |_|(_ | (_)|   .  (initial data setup upon contract deploy)
//==============================================================================
	constructor()
		public
	{
		_admin = msg.sender;
		_cfo = 0x39db0822a5eb167f2f92607d5c77566e23a88aa7;
	}

	modifier onlyCFOAndAdmin()
	{
		require(((msg.sender == _cfo) || (msg.sender == _admin)), "sorry, not cfo/admin");
		_;
	}

	modifier onlyCFO()
	{
		require(msg.sender == _cfo, "sorry, not cfo");
		_;
	}

	modifier isHuman() 
	{
        address _addr = msg.sender;
        uint256 _codeLength;

        assembly {_codeLength := extcodesize(_addr)}
        require(_codeLength == 0, "sorry, humans only");
        _;
    }

	modifier isActivated()
	{
        if ( activated_ == false )
		{
          if (now >= plan_active_time)
		  {
			  activated_ = true;
          }
        }
        require(activated_ == true, "sorry, its not start yet.");
        _;
    }

    function setPlanActiveTime(uint256 _time)
		onlyCFOAndAdmin()
		public
    {
        plan_active_time = _time;
    }

	function getPlanActiveTime()
		public
		view
		returns(uint256, uint256)
    {
        return(plan_active_time, now);
    }

	function newCFO(string addr)
		onlyCFOAndAdmin()
		public 
		returns (bool)
	{
		address newCFOaddress;

		newCFOaddress = parseAddr(addr);

		if (newCFOaddress != _cfo)
		{
			_cfo = newCFOaddress;
			return true;
		}
		else
		{
			return false;
		}
	}

	function distribute(address addr, uint256 ethPay)
		public
		onlyCFOAndAdmin()
		isActivated()
	{
		require((ethPay <= address(this).balance), "sorry, demand more than balance");
		require((ethPay > 0), "sorry, pay zero");

		addr.transfer(ethPay);

		emit onSendEth
		(
			addr,
			ethPay,
			now
		);
	}

	function potAddup()
        external
		onlyCFOAndAdmin()
        payable
    {
        _pot = _pot.add(msg.value);

		emit onPotAddup
		(
			msg.sender,
			msg.value
		);
    }

	function buy()
        public
		isHuman()
        payable
    {
		uint256 _now = now;

		if (activated_ == false)
		{
			require((_now >= plan_active_time), "sorry, buy before start");
			activated_ = true;
		}

		require((msg.value > 0), "sorry, buy zero eth");
		address buyer = msg.sender;

		plyr_[buyer].ethIn = (plyr_[buyer].ethIn).add(msg.value);
		totalETHin = totalETHin.add(msg.value);
		emit onRecieveEth
		(
			buyer,
			msg.value,
			_now
		);
    }
	
    function()
        public
		isHuman()
		isActivated()
        payable
    {
		uint256 _now = now;
		address buyer = msg.sender;

		require((_now >= plan_active_time), "sorry, buy before start");
		require((msg.value > 0), "sorry, buy zero eth");

		plyr_[buyer].ethIn = (plyr_[buyer].ethIn).add(msg.value);
		totalETHin = totalETHin.add(msg.value);
		emit onRecieveEth
		(
			buyer,
			msg.value,
			_now
		);
    }

	function queryhashcodeused(bytes32 hashCode)
		public
		view
		isActivated()
		isHuman()
		returns(bool)
	{
		if((txRec_[hashCode].user != 0) || (txRec_[hashCode].used == true))
		{
			return true;
		}
		else
		{
			return false;
		}
	}
	
	function query2noactive(bytes32 hashCode)
		public
		view
		isHuman()
		returns(bool)
	{
		if((txRec_[hashCode].user != 0) || (txRec_[hashCode].used == true))
		{
			return true;
		}
		else
		{
			return false;
		}
	}

	function withdraw(bytes32 hashCode)
        public
		isActivated()
		isHuman()
    {
		require((plyr_[msg.sender].ethIn > 0), "sorry, not user");
		require((txRec_[hashCode].used != true), "sorry, user replay withdraw");

		txRec_[hashCode].user = msg.sender;
		txRec_[hashCode].todo = true;
		txRec_[hashCode].used = true;
	}

	// uint256 amount, wei format
	function approve(string orderid, string addr, string amt, string txtime, uint256 amount)
		public
        onlyCFO()
		isActivated()
	{
		address user;
		bytes32 hashCode;
		uint256 ethOut;

		user = parseAddr(addr);

		hashCode = sha256(orderid, addr, amt, txtime);

		require((txRec_[hashCode].user == user), "sorry, hashcode error");
		require((txRec_[hashCode].todo == true), "sorry, hashcode replay");

		txRec_[hashCode].todo = false;

		ethOut = amount; // wei format
		require(((ethOut > 0) && (ethOut <= address(this).balance)), "sorry, approve amount error");

		totalETHout = totalETHout.add(ethOut);
		plyr_[user].ethOut = (plyr_[user].ethOut).add(ethOut);
		user.transfer(ethOut);

		emit onSendEth
		(
	        user,
			ethOut,
			now
		);
	}

	function getUserInfo(string useraddress)
		public
		view
		onlyCFOAndAdmin()
		returns(address, uint256, uint256)
	{
		address user;

		user = parseAddr(useraddress);

		return
		(
			user,   // player address
			plyr_[user].ethIn,  // total input
			plyr_[user].ethOut  // total output
		);
	}

	function parseAddr(string _a)
	    internal
	    returns (address)
	{
        bytes memory tmp = bytes(_a);
        uint160 iaddr = 0;
        uint160 b1;
        uint160 b2;
        for (uint i=2; i<2+2*20; i+=2){
            iaddr *= 256;
            b1 = uint160(tmp[i]);
            b2 = uint160(tmp[i+1]);
            if ((b1 >= 97)&&(b1 <= 102)) b1 -= 87;
            else if ((b1 >= 65)&&(b1 <= 70)) b1 -= 55;
            else if ((b1 >= 48)&&(b1 <= 57)) b1 -= 48;
            if ((b2 >= 97)&&(b2 <= 102)) b2 -= 87;
            else if ((b2 >= 65)&&(b2 <= 70)) b2 -= 55;
            else if ((b2 >= 48)&&(b2 <= 57)) b2 -= 48;
            iaddr += (b1*16+b2);
        }
        return address(iaddr);
    }
}

/**
 * @title SafeMath v0.1.9
 * @dev Math operations with safety checks that throw on error
 * change notes:  original SafeMath library from OpenZeppelin modified by Inventor
 * - added sqrt
 * - added sq
 * - added pwr
 * - changed asserts to requires with error log outputs
 * - removed div, its useless
 */
library SafeMath {

    /**
    * @dev Multiplies two numbers, throws on overflow.
    */
    function mul(uint256 a, uint256 b)
        internal
        pure
        returns (uint256 c)
    {
        if (a == 0) {
            return 0;
        }
        c = a * b;
        require(c / a == b, "SafeMath mul failed");
        return c;
    }

    /**
    * @dev Subtracts two numbers, throws on overflow (i.e. if subtrahend is greater than minuend).
    */
    function sub(uint256 a, uint256 b)
        internal
        pure
        returns (uint256)
    {
        require(b <= a, "SafeMath sub failed");
        return a - b;
    }

    /**
    * @dev Adds two numbers, throws on overflow.
    */
    function add(uint256 a, uint256 b)
        internal
        pure
        returns (uint256 c)
    {
        c = a + b;
        require(c >= a, "SafeMath add failed");
        return c;
    }
}