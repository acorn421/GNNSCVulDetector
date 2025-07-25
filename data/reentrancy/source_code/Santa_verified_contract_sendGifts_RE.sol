/*
 * ===== SmartInject Injection Details =====
 * Function      : sendGifts
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 2 findings
 * Total Found   : 9 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding external calls to recipient addresses before and after the token transfer. The vulnerability requires multiple transactions to exploit:
 * 
 * **Specific Changes Made:**
 * 1. Added a low-level `.call()` before the transfer to allow recipient acknowledgment
 * 2. Added a second external call after transfer using `giftReceived(uint256)` callback
 * 3. Used different gas limits (2300 and 5000) to enable different types of reentrancy
 * 
 * **Multi-Transaction Exploitation Pattern:**
 * 1. **Setup Phase (Transaction 1)**: Attacker deploys malicious contract and acquires tokens through normal ICO purchase
 * 2. **Registration Phase (Transaction 2)**: Attacker gets added to santaGiftList by social engineering or other means
 * 3. **Exploitation Phase (Transaction 3)**: When `sendGifts()` is called:
 *    - First `.call()` allows attacker to prepare state
 *    - During `transferFrom()`, attacker can trigger fallback function
 *    - Second `.call()` to `giftReceived()` enables cross-function reentrancy
 *    - Attacker can call other contract functions or manipulate state between callbacks
 * 
 * **Why Multi-Transaction is Required:**
 * - Attacker needs existing token balance from previous transaction to qualify for gifts
 * - The vulnerability depends on the accumulated state of multiple recipients in the array
 * - Cross-function reentrancy allows manipulation of other contract functions between calls
 * - The bonus rate calculation becomes stale as state changes during the loop execution
 * - Each iteration depends on the current state that has been modified by previous iterations
 * 
 * **State Dependencies:**
 * - `balanceOf` mappings persist between transactions and affect bonus calculations
 * - `allowance` mappings are modified during transfers
 * - The loop processes multiple recipients, creating cascading state changes
 * - Bonus calculations depend on current token balances that change during execution
 * 
 * This creates a realistic scenario where an attacker must accumulate tokens over time, get included in gift lists, and then exploit the reentrancy during the actual gift distribution process.
 */
pragma solidity ^0.4.18;

library SafeMath {
    function mul(uint256 a, uint256 b) internal returns(uint256) {
		uint256 c = a * b;
		assert(a == 0 || c / a == b);
		return c;
    }
    
    function div(uint256 a, uint256 b) internal returns(uint256) {
		uint256 c = a / b;
		return c;
    }

    function sub(uint256 a, uint256 b) internal returns(uint256) {
		assert(b <= a);
		return a - b;
    }

    function add(uint256 a, uint256 b) internal returns(uint256) {
		uint256 c = a + b;
		assert(c >= a && c >= b);
		return c;
    }
}

contract Santa {
    
    using SafeMath for uint256; 

    string constant public standard = "ERC20";
    string constant public symbol = "SANTA";
    string constant public name = "Santa";
    uint8 constant public decimals = 18;

    uint256 constant public initialSupply = 1000000 * 1 ether;
    uint256 constant public tokensForIco = 600000 * 1 ether;
    uint256 constant public tokensForBonus = 200000 * 1 ether;

    uint256 constant public startAirdropTime = 1514116800;
    uint256 public startTransferTime;
    uint256 public tokensSold;
    bool public burned;

    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;
    
    uint256 constant public start = 1511136000;
    uint256 constant public end = 1512086399;
    uint256 constant public tokenExchangeRate = 310;
    uint256 public amountRaised;
    bool public crowdsaleClosed = false;
    address public santaFundWallet;
    address ethFundWallet;

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed _owner, address indexed spender, uint256 value);
    event FundTransfer(address backer, uint amount, bool isContribution, uint _amountRaised);
    event Burn(uint256 amount);

    function Santa(address _ethFundWallet) {
		ethFundWallet = _ethFundWallet;
		santaFundWallet = msg.sender;
		balanceOf[santaFundWallet] = initialSupply;
		startTransferTime = end;
    }

    function() payable {
		uint256 amount = msg.value;
		uint256 numTokens = amount.mul(tokenExchangeRate); 
		require(!crowdsaleClosed && now >= start && now <= end && tokensSold.add(numTokens) <= tokensForIco);
		ethFundWallet.transfer(amount);
		balanceOf[santaFundWallet] = balanceOf[santaFundWallet].sub(numTokens); 
		balanceOf[msg.sender] = balanceOf[msg.sender].add(numTokens);
		Transfer(santaFundWallet, msg.sender, numTokens);
		amountRaised = amountRaised.add(amount);
		tokensSold += numTokens;
		FundTransfer(msg.sender, amount, true, amountRaised);
    }

    function transfer(address _to, uint256 _value) returns(bool success) {
		require(now >= startTransferTime); 
		balanceOf[msg.sender] = balanceOf[msg.sender].sub(_value); 
		balanceOf[_to] = balanceOf[_to].add(_value); 
		Transfer(msg.sender, _to, _value); 
		return true;
    }

    function approve(address _spender, uint256 _value) returns(bool success) {
		require((_value == 0) || (allowance[msg.sender][_spender] == 0));
		allowance[msg.sender][_spender] = _value;
		Approval(msg.sender, _spender, _value);
		return true;
    }

    function transferFrom(address _from, address _to, uint256 _value) returns(bool success) {
		if (now < startTransferTime) {
		    require(_from == santaFundWallet);
		}
		var _allowance = allowance[_from][msg.sender];
		require(_value <= _allowance);
		balanceOf[_from] = balanceOf[_from].sub(_value); 
		balanceOf[_to] = balanceOf[_to].add(_value); 
		allowance[_from][msg.sender] = _allowance.sub(_value);
		Transfer(_from, _to, _value);
		return true;
    }

    function burn() internal {
		require(now > startTransferTime);
		require(burned == false);
		uint256 difference = balanceOf[santaFundWallet].sub(tokensForBonus);
		tokensSold = tokensForIco.sub(difference);
		balanceOf[santaFundWallet] = tokensForBonus;
		burned = true;
		Burn(difference);
    }

    function markCrowdsaleEnding() {
		require(now > end);
		burn(); 
		crowdsaleClosed = true;
    }

    function sendGifts(address[] santaGiftList) returns(bool success)  {
	// ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
	require(msg.sender == santaFundWallet);
	require(now >= startAirdropTime);
    
    uint256 bonusRate = tokensForBonus.div(tokensSold); 
	for(uint i = 0; i < santaGiftList.length; i++) {
	    if (balanceOf[santaGiftList[i]] > 0) { 
			uint256 bonus = balanceOf[santaGiftList[i]].mul(bonusRate);
			
			// Vulnerable: External call before state update
			// Allow recipient to potentially trigger callback
			if (santaGiftList[i].call.gas(2300)()) {
				// Recipient acknowledged - proceed with transfer
			}
			
			transferFrom(santaFundWallet, santaGiftList[i], bonus);
			
			// Vulnerable: Additional external call after transfer
			// This enables cross-function reentrancy attacks
			santaGiftList[i].call.gas(5000)(bytes4(keccak256("giftReceived(uint256)")), bonus);
	    }
	}
	return true;
}
	// ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
}