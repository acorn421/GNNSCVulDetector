/*
 * ===== SmartInject Injection Details =====
 * Function      : offerTrade
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 1 findings
 * Total Found   : 1 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-benign (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by:
 * 
 * 1. **External Call Before State Updates**: Added an external call to msg.sender.call() that attempts to notify the user about their trade offer before updating the critical state variables (weiWantedOf and tokensOfferedOf).
 * 
 * 2. **State Manipulation Window**: The tradeActive flag is set to true immediately, but the actual trade parameters (weiWanted and tokensOffered) are updated after the external call. This creates a window where the trade is marked as active but has stale/manipulated parameters.
 * 
 * 3. **Multi-Transaction Exploitation Path**:
 *    - **Transaction 1**: Attacker calls offerTrade() with a malicious contract as msg.sender
 *    - During the external call, the attacker's contract can reenter and call offerTrade() again with different parameters
 *    - This creates a race condition where tradeActive[attacker] = true but the trade parameters may be inconsistent
 *    - **Transaction 2**: A victim calls agreeToTrade(attacker) and executes based on the final state, which may have been manipulated through reentrancy
 * 
 * 4. **Stateful Nature**: The vulnerability exploits the persistent state between transactions:
 *    - The tradeActive mapping persists between transactions
 *    - The weiWantedOf and tokensOfferedOf mappings maintain state that affects future agreeToTrade calls
 *    - An attacker can manipulate these state variables during reentrancy to create inconsistent trade offers
 * 
 * 5. **Why Multi-Transaction is Required**: 
 *    - The vulnerability requires Transaction 1 to set up the malicious state through reentrancy
 *    - Transaction 2 (by a different user calling agreeToTrade) is needed to actually exploit the manipulated state
 *    - The exploit cannot be completed in a single transaction because it depends on another user interacting with the manipulated trade offer
 * 
 * This creates a realistic vulnerability where an attacker can use reentrancy to manipulate their trade offer state, potentially leading to trades being executed with different parameters than what victims expect when they call agreeToTrade in subsequent transactions.
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
    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
    // First update the active status to indicate a trade is being processed
    tradeActive[msg.sender] = true;
    
    // Notify potential trade partners about the new offer via callback
    if (msg.sender.call.value(0)(bytes4(keccak256("onTradeOffer(uint256,uint256)")), _weiWanted, _tokensOffered)) {
        // External call completed successfully
    }
    
    // Update trade parameters after external notification
    weiWantedOf[msg.sender] = _weiWanted;
    tokensOfferedOf[msg.sender] = _tokensOffered;
}
    // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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