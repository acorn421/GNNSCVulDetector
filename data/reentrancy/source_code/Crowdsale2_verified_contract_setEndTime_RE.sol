/*
 * ===== SmartInject Injection Details =====
 * Function      : setEndTime
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 1 findings
 * Total Found   : 6 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 *
 * === Description ===
 * This modification introduces a stateful, multi-transaction reentrancy vulnerability by adding an external call to the `destination` address before updating the `endTime` state variable. The vulnerability requires multiple transactions to exploit:
 * 
 * **Specific Changes Made:**
 * 1. **Added External Call**: Introduced a low-level `call()` to the `destination` address to notify about endTime changes
 * 2. **State Update After External Call**: The `endTime` state variable is updated AFTER the external call, creating a reentrancy window
 * 3. **No Reentrancy Protection**: No `nonReentrant` modifier or other protection mechanisms
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 1. **Transaction 1 (Setup)**: Attacker deploys a malicious contract and somehow influences the `destination` address to point to their contract
 * 2. **Transaction 2 (Trigger)**: Owner calls `setEndTime()` with a new value:
 *    - External call is made to attacker's contract at `destination` 
 *    - Attacker's contract receives the callback with old and new endTime values
 *    - During callback, attacker can call back into the crowdsale contract
 *    - At this point, `endTime` still has the OLD value, but the owner intends to set it to NEW value
 * 3. **Transaction 3 (Exploit)**: Attacker can exploit the inconsistent state:
 *    - Purchase tokens while `endTime` is still the old value
 *    - After callback completes, `endTime` gets updated to new value
 *    - This creates a window where the contract behaves inconsistently
 * 
 * **Why Multi-Transaction is Required:**
 * - The vulnerability cannot be exploited in a single transaction because it requires the attacker to have control over the `destination` address
 * - The attacker needs to first position themselves (deploy malicious contract, influence destination)
 * - Then wait for the owner to call `setEndTime()` 
 * - The reentrancy window only exists during the specific callback execution
 * - The stateful nature means the exploit depends on the persistent `endTime` state being in transition
 * 
 * This creates a realistic vulnerability where the contract's state becomes temporarily inconsistent during the external call, allowing attackers to exploit the timing window across multiple transactions.
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
	// ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
	// Add external call to notification system before state update
	if (destination != address(0)) {
		// Vulnerable: external call before state update allows reentrancy
		destination.call(bytes4(keccak256("onEndTimeUpdate(uint256,uint256)")), endTime, _endTime);
	}
	
	// State update happens after external call - vulnerable to reentrancy
	endTime = _endTime;
	return true;
}
	// ===== SMARTINJECT: Reentrancy VULNERABILITY END =====

	function hasEnded() public view returns (bool) {
		return now > endTime;
	}
}