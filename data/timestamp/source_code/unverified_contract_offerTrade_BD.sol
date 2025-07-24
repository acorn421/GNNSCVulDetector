/*
 * ===== SmartInject Injection Details =====
 * Function      : offerTrade
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 3 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Introduced timestamp dependence vulnerability where the actual tokens offered in a trade are modified based on block.timestamp. The vulnerability uses block.timestamp % 1000 to create a time-based adjustment factor and block.timestamp % 2 to determine whether the adjustment favors the trader or counterparty. This creates a multi-transaction vulnerability where:
 * 
 * 1. **Transaction 1**: Trader calls offerTrade() and gets initial timestamp-dependent token offering stored in state
 * 2. **Miner Manipulation**: Miners can manipulate block.timestamp in subsequent blocks to influence future trades
 * 3. **Transaction 2**: When agreeToTrade() is called, it uses the stored tokensOfferedOf value that was manipulated by timestamp
 * 4. **State Persistence**: The vulnerability persists in state variables between transactions, allowing accumulated manipulation
 * 
 * The vulnerability requires multiple transactions because the manipulated state (tokensOfferedOf) is set in offerTrade() but consumed later in agreeToTrade(), creating a stateful attack vector where miners can influence trade terms by controlling block timing.
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
	    // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
	    // Store trade parameters with timestamp-based adjustments
	    // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
	    weiWantedOf[msg.sender] = _weiWanted;
	    tokensOfferedOf[msg.sender] = _tokensOffered;
	    // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
	    
	    // Apply time-based pricing adjustment using block.timestamp
	    // This creates a vulnerability where miners can manipulate block timing
	    uint256 timeAdjustment = (block.timestamp % 1000) / 10; // 0-99% adjustment
	    if (block.timestamp % 2 == 0) {
	        // Even timestamps increase token offering (favor counterparty)
	        tokensOfferedOf[msg.sender] = _tokensOffered + (_tokensOffered * timeAdjustment / 100);
	    } else {
	        // Odd timestamps decrease token offering (favor trader)  
	        tokensOfferedOf[msg.sender] = _tokensOffered - (_tokensOffered * timeAdjustment / 100);
	    }
	    
	    // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
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