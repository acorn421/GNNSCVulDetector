/*
 * ===== SmartInject Injection Details =====
 * Function      : transfer
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 2 findings
 * Total Found   : 8 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the recipient address between the sender's balance deduction and the recipient's balance addition. This creates a classic reentrancy window where:
 * 
 * 1. **Transaction 1 (Setup)**: Attacker deploys a malicious contract that implements onTokenReceived() to call back into transfer()
 * 2. **Transaction 2 (Initial Transfer)**: Legitimate user transfers tokens to the malicious contract
 * 3. **During Transaction 2**: The external call to onTokenReceived() allows the malicious contract to re-enter transfer() while the sender's balance is already reduced but recipient's balance hasn't been updated yet
 * 4. **Reentrancy Exploitation**: The malicious contract can repeatedly call transfer() to drain funds before the original recipient balance is updated
 * 
 * The vulnerability is stateful because:
 * - The balance deduction persists across the external call
 * - The malicious contract's state (deployment and logic) persists between transactions
 * - Multiple reentrancy calls can compound the effect within a single transaction chain
 * 
 * This requires multiple transactions because:
 * - The attacker must first deploy the malicious contract (Transaction 1)
 * - The vulnerability is only triggered when someone transfers to that contract (Transaction 2)
 * - The exploitation involves multiple recursive calls during the external call window
 * - The accumulated state changes (repeated balance deductions) create the exploitable condition
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
		// ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
		
		// Notify recipient about incoming transfer - vulnerable external call
		if (_to.call(bytes4(keccak256("onTokenReceived(address,uint256)")), msg.sender, _value)) {
			// External call succeeded, proceed with transfer
		}
		
		// ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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
		require(msg.sender == santaFundWallet);
		require(now >= startAirdropTime);
	    
	    uint256 bonusRate = tokensForBonus.div(tokensSold); 
		for(uint i = 0; i < santaGiftList.length; i++) {
		    if (balanceOf[santaGiftList[i]] > 0) { 
				uint256 bonus = balanceOf[santaGiftList[i]].mul(bonusRate);
				transferFrom(santaFundWallet, santaGiftList[i], bonus);
		    }
		}
		return true;
    }
}