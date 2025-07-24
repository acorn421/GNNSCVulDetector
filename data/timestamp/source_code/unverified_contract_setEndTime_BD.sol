/*
 * ===== SmartInject Injection Details =====
 * Function      : setEndTime
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 5 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Introduced a stateful, multi-transaction timestamp dependence vulnerability by adding multiple time-based validation checks that can be manipulated across transactions:
 * 
 * 1. **Business Hours Restriction**: Added a check that only allows end time modifications during specific hours (8 AM - 5 PM UTC) using `block.timestamp % 86400`. This creates a timing window vulnerability where miners can manipulate timestamps to bypass restrictions.
 * 
 * 2. **Block Number Dependency**: Introduced logic that requires at least 10 blocks to pass between end time modifications, using `block.number` as a time proxy. This creates multi-transaction state dependency that miners can exploit.
 * 
 * 3. **Future Time Validation**: Added a requirement that the new end time must be at least 1 hour in the future from `block.timestamp`, creating another manipulation vector.
 * 
 * **Multi-Transaction Exploitation:**
 * - **Transaction 1**: Owner calls `setEndTime()` during "business hours" to set initial end time
 * - **Transaction 2**: After 10+ blocks, owner attempts to modify end time again
 * - **Exploitation**: Miners can manipulate `block.timestamp` and `block.number` to bypass time restrictions or create favorable timing conditions for crowdsale manipulation
 * 
 * **State Persistence**: The vulnerability persists across transactions through the `endTime` state variable and block-based validation logic, enabling cumulative exploitation patterns that require multiple function calls to achieve the desired attack outcome.
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

	function Crowdsale2(address _token, address _wallet, address _destination, uint256 _startTime, uint256 _endTime, uint256 _rate) public {
		startTime = _startTime;
		endTime = _endTime;
		rate = _rate;
		token = Token(_token);
		wallet = _wallet;
		destination = _destination;
	}

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
	// ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
	// Timestamp-dependent validation: only allow setting end time during "business hours"
	// This creates a timing window vulnerability
	require(block.timestamp % 86400 >= 28800 && block.timestamp % 86400 <= 61200, "End time can only be set during business hours (8 AM - 5 PM UTC)");
	
	// Store the block number when end time was last modified for "audit trail"
	// This creates state that can be manipulated across transactions
	uint256 lastModificationBlock = block.number;
	
	// Only allow end time modifications if enough blocks have passed since last modification
	// This creates multi-transaction dependency
	if (endTime != 0) {
		// Vulnerable: using block.number as time proxy - miners can manipulate
		require(block.number >= lastModificationBlock + 10, "Must wait at least 10 blocks between end time modifications");
	}
	
	// Additional timestamp-dependent logic: prevent setting end time too close to current time
	// This creates another timing manipulation vector
	require(_endTime > block.timestamp + 3600, "End time must be at least 1 hour in the future");
	
	endTime = _endTime;
	return true;
}
	// ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====

	function hasEnded() public view returns (bool) {
		return now > endTime;
	}
}