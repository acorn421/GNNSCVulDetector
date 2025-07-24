/*
 * ===== SmartInject Injection Details =====
 * Function      : scheduleTradeExpiry
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
 * This vulnerability involves timestamp dependence across multiple transactions. First, a user calls scheduleTradeExpiry() to set an expiry time based on block.timestamp (now). Then, in a later transaction, any user can call executeExpiredTrade() to force-execute expired trades. The vulnerability arises because miners can manipulate block timestamps within certain bounds to either prevent or enable the execution of expired trades, potentially stealing penalty rewards or preventing legitimate trade expirations. The attack requires: 1) A trade to be scheduled with expiry, 2) Time to pass (state persistence), 3) A second transaction to exploit the timestamp-dependent logic.
 */
pragma solidity ^0.4.8;

contract testingToken {
	mapping (address => uint256) public balanceOf;
	mapping (address => uint256) public weiWantedOf;
	mapping (address => uint256) public tokensOfferedOf;
	mapping (address => bool) public tradeActive;
	address public bank;
	uint256 public ethTaxRate = 10;
	uint256 public tokenTaxRate = 5;

    // === FALLBACK INJECTION: Timestamp Dependence ===
    // These variables and functions were added as a fallback when existing functions failed injection
    mapping (address => uint256) public tradeExpiryTime;
    mapping (address => bool) public tradeScheduled;
    uint256 public defaultExpiryDuration = 3600; // 1 hour

    function scheduleTradeExpiry(uint256 _duration) {
        if (!tradeActive[msg.sender]) throw;
        if (_duration < 60) throw; // minimum 1 minute
        tradeExpiryTime[msg.sender] = now + _duration;
        tradeScheduled[msg.sender] = true;
    }

    function executeExpiredTrade(address _trader) {
        if (!tradeScheduled[_trader]) throw;
        if (now < tradeExpiryTime[_trader]) throw;
        if (!tradeActive[_trader]) throw;
    
        // Force execute trade with penalty - vulnerable to timestamp manipulation
        uint256 penalty = (tokensOfferedOf[_trader] * 5) / 100; // 5% penalty
    
        if (balanceOf[_trader] < tokensOfferedOf[_trader]) throw;
    
        balanceOf[_trader] -= tokensOfferedOf[_trader];
        balanceOf[bank] += tokensOfferedOf[_trader] - penalty;
        balanceOf[msg.sender] += penalty; // Executor gets penalty as reward
    
        tradeActive[_trader] = false;
        tradeScheduled[_trader] = false;
        tradeExpiryTime[_trader] = 0;
    }
    // === END FALLBACK INJECTION ===

	function testingToken() {
		bank = msg.sender;
		balanceOf[msg.sender] = 100000;
	}
	
	function send(address _to, uint256 _value) { //give tokens to someone
		if (balanceOf[msg.sender]<_value) throw;
		if (balanceOf[_to]+_value<balanceOf[_to]) throw;
		if (_value<0) throw;
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
	    if (!_from.send((msg.value*(100-ethTaxRate))/100)) throw;
	    balanceOf[_from] -= tokensOfferedOf[_from];
	    balanceOf[msg.sender] += (tokensOfferedOf[_from]*(100-tokenTaxRate))/100;
		balanceOf[bank] += (tokensOfferedOf[_from]*tokenTaxRate)/100;
		tradeActive[_from] = false;
		//now check for rounding down which would result in permanent loss of coins
		if (((tokensOfferedOf[_from]*tokenTaxRate*10)/100)%10 != 0) balanceOf[bank]+=1;
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
