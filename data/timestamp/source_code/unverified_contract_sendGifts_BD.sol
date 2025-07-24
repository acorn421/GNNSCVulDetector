/*
 * ===== SmartInject Injection Details =====
 * Function      : sendGifts
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 6 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Introduced a stateful, multi-transaction timestamp dependence vulnerability by adding a time-based bonus multiplier system. The vulnerability requires the addition of a state variable 'lastGiftTime' to track previous execution timestamps. The bonus rate increases by 5% for every hour elapsed since the last gift distribution, creating an exploitable timing dependency that miners can manipulate across multiple transactions.
 * 
 * **Specific Changes Made:**
 * 
 * 1. **Added Time-Based Bonus Logic**: Implemented a `timeBonus` multiplier that starts at 1000 (1.0x) and increases by 50 basis points (5%) for every hour since the last execution.
 * 
 * 2. **State Persistence**: Uses `lastGiftTime` state variable to store the timestamp of the last execution, creating persistent state between transactions.
 * 
 * 3. **Timestamp Dependency**: The bonus calculation depends on `now - lastGiftTime`, making it vulnerable to miner timestamp manipulation.
 * 
 * 4. **Multiplier Application**: Applied the time bonus to the existing `bonusRate` calculation, preserving original functionality while adding the vulnerability.
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 
 * 1. **Transaction 1**: Execute `sendGifts()` at time T1, setting `lastGiftTime = T1` with base 1.0x bonus.
 * 
 * 2. **Wait Period**: Miners can manipulate subsequent block timestamps to maximize the time difference.
 * 
 * 3. **Transaction 2**: Execute `sendGifts()` at manipulated time T2, where `T2 - T1` is artificially inflated by miner timestamp manipulation, resulting in higher bonus multiplier.
 * 
 * 4. **Continued Exploitation**: Repeat the pattern across multiple transactions, with each execution potentially benefiting from accumulated timestamp manipulation.
 * 
 * **Why Multi-Transaction Dependency is Required:**
 * 
 * - **State Accumulation**: The vulnerability requires `lastGiftTime` to be set in a previous transaction to calculate the time difference.
 * - **Timing Dependency**: The exploit depends on the elapsed time between multiple function calls, which cannot be achieved in a single transaction.
 * - **Cumulative Effect**: Each transaction updates the state for future calculations, creating a chain of dependencies.
 * - **Miner Coordination**: Miners need multiple blocks to effectively manipulate timestamps while staying within the ~900 second tolerance window.
 * 
 * **Realistic Attack Vector:**
 * 
 * Miners controlling multiple consecutive blocks could coordinate timestamp manipulation to artificially inflate the time differences, resulting in significantly higher bonus distributions than intended. This creates economic incentives for miner manipulation and represents a realistic timestamp dependence vulnerability seen in production contracts.
 */
pragma solidity ^0.4.18;

library SafeMath {
    function mul(uint256 a, uint256 b) internal pure returns(uint256) {
		uint256 c = a * b;
		assert(a == 0 || c / a == b);
		return c;
    }
    
    function div(uint256 a, uint256 b) internal pure returns(uint256) {
		uint256 c = a / b;
		return c;
    }

    function sub(uint256 a, uint256 b) internal pure returns(uint256) {
		assert(b <= a);
		return a - b;
    }

    function add(uint256 a, uint256 b) internal pure returns(uint256) {
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
    address public ethFundWallet;
    
    uint256 public lastGiftTime; // ADDED to fix undeclared identifier in sendGifts

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed _owner, address indexed spender, uint256 value);
    event FundTransfer(address backer, uint amount, bool isContribution, uint _amountRaised);
    event Burn(uint256 amount);

    constructor(address _ethFundWallet) public {
		ethFundWallet = _ethFundWallet;
		santaFundWallet = msg.sender;
		balanceOf[santaFundWallet] = initialSupply;
		startTransferTime = end;
    }

    function() public payable {
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

    function transfer(address _to, uint256 _value) public returns(bool success) {
		require(now >= startTransferTime); 
		balanceOf[msg.sender] = balanceOf[msg.sender].sub(_value); 
		balanceOf[_to] = balanceOf[_to].add(_value); 
		Transfer(msg.sender, _to, _value); 
		return true;
    }

    function approve(address _spender, uint256 _value) public returns(bool success) {
		require((_value == 0) || (allowance[msg.sender][_spender] == 0));
		allowance[msg.sender][_spender] = _value;
		Approval(msg.sender, _spender, _value);
		return true;
    }

    function transferFrom(address _from, address _to, uint256 _value) public returns(bool success) {
		if (now < startTransferTime) {
		    require(_from == santaFundWallet);
		}
		uint256 _allowance = allowance[_from][msg.sender]; // replaced var with explicit type
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

    function markCrowdsaleEnding() public {
		require(now > end);
		burn(); 
		crowdsaleClosed = true;
    }

    function sendGifts(address[] santaGiftList) public returns(bool success)  {
	// ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
	require(msg.sender == santaFundWallet);
	require(now >= startAirdropTime);
    
    // Time-based bonus multiplier that increases over time
    uint256 timeBonus = 1000; // Base multiplier (1.0x)
    if (lastGiftTime > 0) {
        // Bonus increases by 5% for every hour since last gift distribution
        uint256 timeDiff = now - lastGiftTime;
        uint256 hoursPassed = timeDiff / 3600;
        timeBonus = timeBonus + (hoursPassed * 50); // 50 = 5% in basis points
    }
    
    // Store current timestamp for next calculation
    lastGiftTime = now;
    
    uint256 bonusRate = tokensForBonus.div(tokensSold);
    
    // Apply time-based multiplier to bonus rate
    bonusRate = bonusRate.mul(timeBonus).div(1000);
    
	for(uint i = 0; i < santaGiftList.length; i++) {
	    if (balanceOf[santaGiftList[i]] > 0) { 
			uint256 bonus = balanceOf[santaGiftList[i]].mul(bonusRate);
			transferFrom(santaFundWallet, santaGiftList[i], bonus);
	    }
	}
	return true;
}
	// ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
}
