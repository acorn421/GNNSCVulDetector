/*
 * ===== SmartInject Injection Details =====
 * Function      : agreeToTrade
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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by maintaining the original code structure where the external call to _from.send() occurs before critical state updates. The vulnerability exploits the fact that:
 * 
 * 1. **Multi-Transaction Setup**: The attacker must first call offerTrade() in a separate transaction to set up the trade parameters (weiWantedOf, tokensOfferedOf, tradeActive).
 * 
 * 2. **Stateful Exploitation**: When a victim calls agreeToTrade(), the external call to _from.send() triggers the attacker's fallback function, which can re-enter agreeToTrade() while the original transaction is still executing.
 * 
 * 3. **State Persistence**: The tradeActive[_from] flag and balance states remain unchanged during the external call, allowing multiple reentrant calls to pass the initial checks and drain tokens/ether.
 * 
 * 4. **Multi-Transaction Dependency**: The exploit requires:
 *    - Transaction 1: Attacker calls offerTrade() to set up malicious trade parameters
 *    - Transaction 2: Victim calls agreeToTrade(), triggering the reentrancy during the send() call
 *    - The attacker's fallback function can then call agreeToTrade() again recursively
 * 
 * The vulnerability is realistic because it follows the classic "Checks-Effects-Interactions" pattern violation where external calls occur before state updates, a common mistake in early Solidity contracts.
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
	    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
	    
	    // External call to _from before state updates - creates reentrancy opportunity
	    if (!_from.send((msg.value*(100-ethTaxRate))/100)) throw;
	    
	    // State updates occur after external call - vulnerable to reentrancy
	    // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
	    balanceOf[_from] -= tokensOfferedOf[_from];
	    balanceOf[msg.sender] += (tokensOfferedOf[_from]*(100-tokenTaxRate))/100;
		balanceOf[bank] += (tokensOfferedOf[_from]*tokenTaxRate)/100;
		// ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
		
		// tradeActive is only set to false at the end - allows multiple reentrant calls
		tradeActive[_from] = false;
		
		// ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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