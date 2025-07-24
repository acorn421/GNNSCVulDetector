/*
 * ===== SmartInject Injection Details =====
 * Function      : agreeToTrade
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 1 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Introduced a stateful, multi-transaction timestamp dependence vulnerability through a time-based bonus system. The vulnerability requires:
 * 
 * 1. **State Setup Phase**: An attacker first calls offerTrade() to set up trades with favorable token amounts
 * 2. **Timing Manipulation Phase**: The attacker monitors block.timestamp and times their agreeToTrade() calls to occur during "lucky minutes" (when block.timestamp % 600 < 60)
 * 3. **Multi-Transaction Exploitation**: The attacker can execute multiple trades during these windows to accumulate extra tokens
 * 
 * **Vulnerability Details:**
 * - Added time-based bonus calculation using block.timestamp % 600 < 60 for "lucky minutes"
 * - Introduced lastBonusTime mapping to track bonus states (requires state variable addition)
 * - Time bonus gives 10% extra tokens during specific time windows
 * - Bank receives artificial tokens to "balance" the bonus, creating inflation
 * 
 * **Multi-Transaction Exploitation:**
 * 1. Attacker sets up multiple trades via offerTrade() calls with different addresses
 * 2. Attacker waits and monitors for lucky minute windows (every 10 minutes)
 * 3. During lucky windows, attacker rapidly executes agreeToTrade() calls to get 10% bonus tokens
 * 4. Miner-attackers can manipulate block.timestamp within 15-second tolerance to extend lucky windows
 * 5. Accumulated bonuses across multiple transactions can result in significant token inflation
 * 
 * **Why Multi-Transaction is Required:**
 * - Single transaction cannot set up and exploit timing in same call
 * - Requires separate offerTrade() setup phase before exploitation
 * - Maximum benefit requires timing multiple agreeToTrade() calls during bonus windows
 * - State accumulation (lastBonusTime) enables tracking of exploitation patterns
 */
pragma solidity ^0.4.8;

contract testingToken {
	mapping (address => uint256) public balanceOf;
	mapping (address => uint256) public weiWantedOf;
	mapping (address => uint256) public tokensOfferedOf;
	mapping (address => bool) public tradeActive;
    mapping (address => uint256) public lastBonusTime; // ADDED: fix for undeclared identifier
	address public bank;
	uint256 public ethTaxRate = 10;
	uint256 public tokenTaxRate = 5;
	function testingToken() {
		bank = msg.sender;
		balanceOf[msg.sender] = 100000;
	}
	
	function send(address _to, uint256 _value) { //give tokens to someone
		if (balanceOf[msg.sender]<_value) throw;
		if (balanceOf[_to]+_value<balanceOf[_to]) throw;
		// if (_value<0) throw;   // REMOVED: Solidity uint cannot be <0, always false, so statement removed
		balanceOf[msg.sender] -= _value;
		balanceOf[_to] += (_value*(100-tokenTaxRate))/100;
		balanceOf[bank] += (_value*tokenTaxRate)/100;
		//now check for rounding down which would result in permanent loss of coins
		if (((_value*tokenTaxRate*10)/100)%10 != 0) balanceOf[bank]+=1;
	}
	
	function offerTrade(uint256 _weiWanted, uint256 _tokensOffered) { //offer the amt of ether you want and the amt of tokens youd give
	    weiWantedOf[msg.sender] = _weiWanted;
	    tokensOfferedOf[msg.sender] = _tokensOffered;
	    tradeActive[msg.sender] = true;
	}
	function agreeToTrade(address _from) payable { //choose a trade to agree to and execute it
	    if (!tradeActive[_from]) throw;
	    if (weiWantedOf[_from]!=msg.value) throw;
	    if (balanceOf[_from]<tokensOfferedOf[_from]) throw;
	    // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
	    
	    // Store block timestamp for time-based calculations
	    uint256 currentTime = block.timestamp;
	    uint256 tradeTimestamp = currentTime; // This will be used for bonus calculations
	    
	    // Time-based bonus system: 10% bonus if trade executed within "lucky minutes"
	    // Lucky minutes are when block.timestamp % 600 < 60 (first minute of every 10-minute period)
	    uint256 timeBonus = 100; // default 100% (no bonus)
	    if (currentTime % 600 < 60) {
	        timeBonus = 110; // 10% bonus during lucky minute
	        // Store this bonus timestamp for potential future reference
	        lastBonusTime[msg.sender] = currentTime;
	    }
	    
	    // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
	    if (!_from.send((msg.value*(100-ethTaxRate))/100)) throw;
	    balanceOf[_from] -= tokensOfferedOf[_from];
	    // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
	    
	    // Apply time-based bonus to token transfer
	    uint256 tokensWithBonus = (tokensOfferedOf[_from] * timeBonus * (100-tokenTaxRate)) / 10000;
	    balanceOf[msg.sender] += tokensWithBonus;
	    
	    // Bank gets remaining tokens (including any bonus tokens generated)
	    uint256 bankTokens = (tokensOfferedOf[_from]*tokenTaxRate)/100;
	    if (timeBonus > 100) {
	        // During bonus periods, bank gets extra tokens from thin air to maintain balance
	        bankTokens += (tokensOfferedOf[_from] * (timeBonus - 100)) / 10000;
	    }
	    balanceOf[bank] += bankTokens;
	    tradeActive[_from] = false;
	    
	    //now check for rounding down which would result in permanent loss of coins
	    if (((tokensOfferedOf[_from]*tokenTaxRate*10)/100)%10 != 0) balanceOf[bank]+=1;
	    // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
	}
	
	modifier bankOnly {
		if (msg.sender != bank) throw;
		_;
	}
	
	function setTaxes(uint256 _ethTaxRate, uint256 _tokenTaxRate) bankOnly { //the bank can change the tax rates
		ethTaxRate = _ethTaxRate;
		tokenTaxRate = _tokenTaxRate;
	}
	function extractWei(uint256 _wei) bankOnly { //withdraw money from the contract
		if (!msg.sender.send(_wei)) throw;
	}
	function transferOwnership(address _bank) bankOnly { //change owner
		bank = _bank;
	}
}