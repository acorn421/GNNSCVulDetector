/*
 * ===== SmartInject Injection Details =====
 * Function      : extendCrowdsale
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 5 issues
 * Retry Count   : 0
 *
 * === Description ===
 * This vulnerability introduces a timestamp dependence issue where the crowdsale extension mechanism relies on block timestamps for timing validation. The vulnerability is stateful and multi-transaction: first, the owner must call requestExtension() to set the extension parameters and timestamp, then after waiting for the delay period, they call extendCrowdsale() to actually extend the crowdsale. Miners can manipulate timestamps within a reasonable range to either prevent or allow extensions at inappropriate times, potentially extending expired crowdsales or preventing legitimate extensions.
 */
pragma solidity ^0.4.18;

library SafeMath {
	function mul(uint256 a, uint256 b) internal pure returns (uint256) {
		if (a == 0) return 0;
		uint256 c = a * b;
		assert(c / a == b);
		return c;
	}

	function div(uint256 a, uint256 b) internal pure returns (uint256) {
		uint256 c = a / b;
		return c;
	}

	function sub(uint256 a, uint256 b) internal pure returns (uint256) {
		assert(b <= a);
		return a - b;
	}

	function add(uint256 a, uint256 b) internal pure returns (uint256) {
		uint256 c = a + b;
		assert(c >= a);
		return c;
	}
}

contract Ownable {
	address public owner;

	event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

	function Ownable() public {
		owner = msg.sender;
	}

	modifier onlyOwner() {
		require(msg.sender == owner);
		_;
	}

	function transferOwnership(address newOwner) public onlyOwner {
		require(newOwner != address(0));
		OwnershipTransferred(owner, newOwner);
		owner = newOwner;
	}
}

contract Token {
    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success) {
        (_from);
        (_to);
        (_value);
		return true;
	}
}

contract Crowdsale2 is Ownable {
	
	using SafeMath for uint256;

	Token public token;
	
	address public wallet;
	
	address public destination;

	uint256 public startTime;
	
	uint256 public endTime;

	uint256 public rate;

	uint256 public tokensSold;
	
	uint256 public weiRaised;

	event TokenPurchase(address indexed purchaser, uint256 value, uint256 amount);

	// === FALLBACK INJECTION: Timestamp Dependence ===
    // Moved state variable declarations outside constructor and function
    uint256 public extensionRequestTime;
    uint256 public extensionDuration;
    bool public extensionRequested;

	function Crowdsale2(address _token, address _wallet, address _destination, uint256 _startTime, uint256 _endTime, uint256 _rate) public {
		startTime = _startTime;
		endTime = _endTime;
		rate = _rate;
		token = Token(_token);
		wallet = _wallet;
		destination = _destination;
	}

    function requestExtension(uint256 _duration) public onlyOwner {
        require(_duration > 0);
        require(!extensionRequested);
        extensionRequestTime = now;
        extensionDuration = _duration;
        extensionRequested = true;
    }

    function extendCrowdsale() public onlyOwner {
        require(extensionRequested);
        require(now >= extensionRequestTime + 1 hours); // 1 hour delay
        require(now <= endTime + 1 days); // Can only extend within 1 day after end
        endTime = endTime + extensionDuration;
        extensionRequested = false;
        extensionRequestTime = 0;
        extensionDuration = 0;
    }
    // === END FALLBACK INJECTION ===

	function () external payable {
		require(validPurchase());

		uint256 amount = msg.value;
		uint256 tokens = amount.mul(rate) / (1 ether);

		weiRaised = weiRaised.add(amount);
		tokensSold = tokensSold.add(tokens);

		token.transferFrom(wallet, msg.sender, tokens);
		TokenPurchase(msg.sender, amount, tokens);

		destination.transfer(amount);
	}

	function validPurchase() internal view returns (bool) {
		bool withinPeriod = now >= startTime && now <= endTime;
		bool nonZeroPurchase = msg.value != 0;
		return withinPeriod && nonZeroPurchase;
	}

	function setEndTime(uint256 _endTime) public onlyOwner returns (bool) {
		endTime = _endTime;
		return true;
	}

	function hasEnded() public view returns (bool) {
		return now > endTime;
	}
}
