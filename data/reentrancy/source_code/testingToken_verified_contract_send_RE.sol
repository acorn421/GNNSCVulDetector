/*
 * ===== SmartInject Injection Details =====
 * Function      : send
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 2 findings
 * Total Found   : 2 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-benign (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by:
 * 
 * 1. **Added State Variables**: 
 *    - `pendingTransfers` mapping to track pending transfer amounts
 *    - `transferInProgress` mapping to track transfer status
 * 
 * 2. **Specific Vulnerability Injection**:
 *    - Added external call to recipient contract (`_to.call(...)`) BEFORE state updates
 *    - State modifications (balance updates) occur AFTER the external call
 *    - Transfer process can be left in a pending state if callback fails
 * 
 * 3. **Multi-Transaction Exploitation Path**:
 *    - **Transaction 1**: Attacker calls `send()` with malicious recipient contract that fails the callback, leaving transfer in pending state with `transferInProgress[attacker] = true` and `pendingTransfers[attacker] = value`
 *    - **Transaction 2**: Attacker calls `send()` again. The function checks balance against original amount, but the previous pending transfer state still exists
 *    - **Transaction 3**: Attacker's malicious contract succeeds in callback, completing multiple transfers while only having balance checked once
 * 
 * 4. **Stateful Nature**:
 *    - `transferInProgress` and `pendingTransfers` persist between transactions
 *    - Failed callbacks leave the contract in an inconsistent state
 *    - Multiple pending transfers can accumulate before being processed
 * 
 * 5. **Realistic Implementation**:
 *    - Transfer notification callbacks are common in modern token contracts
 *    - Pending transfer retry mechanisms exist in production systems
 *    - The vulnerability mimics real-world patterns where external calls precede state updates
 * 
 * **Exploitation Requires Multiple Transactions**:
 * - Single transaction cannot exploit this due to the stateful nature
 * - Requires building up pending transfer state across multiple calls
 * - The vulnerability emerges from the interaction between persistent state and external calls across transaction boundaries
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
	
	// ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
mapping (address => uint256) public pendingTransfers;
mapping (address => bool) public transferInProgress;

function send(address _to, uint256 _value) { //give tokens to someone
	if (balanceOf[msg.sender]<_value) throw;
	if (balanceOf[_to]+_value<balanceOf[_to]) throw;
	if (_value<0) throw;
	
	// Mark transfer as in progress for multi-transaction processing
	transferInProgress[msg.sender] = true;
	pendingTransfers[msg.sender] = _value;
	
	// External call to recipient for transfer notification BEFORE state updates
	if (_to.call(bytes4(keccak256("onTokenReceived(address,uint256)")), msg.sender, _value)) {
		// State updates happen after external call - vulnerable to reentrancy
// ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
		balanceOf[msg.sender] -= _value;
		balanceOf[_to] += (_value*(100-tokenTaxRate))/100;
		balanceOf[bank] += (_value*tokenTaxRate)/100;
		// ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
		
		// Complete the transfer process
		transferInProgress[msg.sender] = false;
		pendingTransfers[msg.sender] = 0;
		
		// ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
		//now check for rounding down which would result in permanent loss of coins
		if (((_value*tokenTaxRate*10)/100)%10 != 0) balanceOf[bank]+=1;
	// ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
	} else {
		// If callback fails, leave transfer in pending state for retry
		// This creates persistent state that can be exploited later
	}
}
	// ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
	
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