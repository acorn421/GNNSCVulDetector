/*
 * ===== SmartInject Injection Details =====
 * Function      : buyTokens
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 3 findings
 * Total Found   : 3 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-benign (SWC-107)
 * 3. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to a user-controlled tokenDistributor contract before state updates. This creates a classic violation of the Checks-Effects-Interactions pattern where:
 * 
 * 1. **State Dependency**: The vulnerability exploits the fact that the maxGoal check uses the current amountRaised value, which hasn't been updated yet when the external call occurs.
 * 
 * 2. **Multi-Transaction Setup**: The attack requires multiple transactions:
 *    - Transaction 1: Set up malicious tokenDistributor contract
 *    - Transaction 2: Call buyTokens() to trigger the vulnerable callback
 *    - Transaction 3+: Reentrant calls through the callback exploit stale state
 * 
 * 3. **Stateful Exploitation**: The vulnerability accumulates state across multiple calls:
 *    - Each reentrant call sees the same stale amountRaised value
 *    - This allows bypassing the maxGoal limit through accumulated purchases
 *    - The payments mapping tracks contributions that can be exploited in subsequent transactions
 * 
 * 4. **Realistic Context**: The tokenDistributor callback fits naturally in a crowdsale context for "token distribution notifications" or "purchase confirmations", making this a realistic vulnerability pattern.
 * 
 * The exploit requires setting up the attack infrastructure first, then using the callback mechanism to perform reentrant calls that bypass the crowdsale limits through stale state reads.
 */
pragma solidity ^0.4.24;

/**
 * @title Owned
 * @dev Contract that sets an owner, who can execute predefined functions, only accessible by him
 */
contract Owned {
	address public owner;

	constructor() public {
		owner = msg.sender;
	}

	modifier onlyOwner {
		require(msg.sender == owner);
		_;
	}

	function transferOwnership(address newOwner) onlyOwner public {
		require(newOwner != 0x0);
		owner = newOwner;
	}
}

/**
 * @title SafeMath
 * @dev Mathematical functions to check for overflows
 */
contract SafeMath {
	function safeAdd(uint256 a, uint256 b) internal pure returns (uint256) {
		uint256 c = a + b;
		assert(c >= a && c >= b);

		return c;
	}
}

// Interface for the external token distributor contract
interface ITokenDistributor {
    function notifyPurchase(address buyer, uint256 amount) external;
}

contract CURESSale is Owned, SafeMath {
	uint256 public maxGoal = 175000 * 1 ether;			// Hard Cap in Ethereum
	uint256 public minTransfer = 5 * 1 ether;			// Minimum amount in EHT that can be send
	uint256 public amountRaised = 0;					// The raised amount in ETH Wei
	mapping(address => uint256) public payments;		// How much ETH the user sent
	bool public isFinalized = false;					// Indicates if the Private Sale is finalized

    address public tokenDistributor; // Address for token distributor contract

	// Public event on the blockchain, to notify users when a Payment is made
	event PaymentMade(address indexed _from, uint256 _ammount);

	/**
	 * @dev The default function called when anyone sends funds (ETH) to the contract
	 */
	function() payable public {
		buyTokens();
	}

	function buyTokens() payable public returns (bool success) {
		// Check if finalized
		require(!isFinalized);

		uint256 amount = msg.value;

		// Check if the goal is reached
		uint256 collectedEth = safeAdd(amountRaised, amount);
		require(collectedEth <= maxGoal);

		require(amount >= minTransfer);

		// ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
		// Notify token distributor before state updates (vulnerable pattern)
		if (tokenDistributor != address(0)) {
			ITokenDistributor(tokenDistributor).notifyPurchase(msg.sender, amount);
		}

		// ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
		payments[msg.sender] = safeAdd(payments[msg.sender], amount);
		amountRaised = safeAdd(amountRaised, amount);

		owner.transfer(amount);

		emit PaymentMade(msg.sender, amount);
		return true;
	}

	// In case of any ETH left at the contract
	// Can be used only after the Sale is finalized
	function withdraw(uint256 _value) public onlyOwner {
		require(isFinalized);
		require(_value > 0);

		msg.sender.transfer(_value);
	}

	function changeMinTransfer(uint256 min) external onlyOwner {
		require(!isFinalized);

		require(min > 0);

		minTransfer = min;
	}

	// CURES finalizes the Sale
	function finalize() external onlyOwner {
		require(!isFinalized);

		// Finalize the Sale
		isFinalized = true;
	}
}
