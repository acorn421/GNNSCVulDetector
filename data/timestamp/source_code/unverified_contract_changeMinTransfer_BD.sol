/*
 * ===== SmartInject Injection Details =====
 * Function      : changeMinTransfer
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 0 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Introduced a stateful, multi-transaction Timestamp Dependence vulnerability by adding time-based calculations that reduce the minimum transfer amount based on the time elapsed since the last change. The vulnerability requires:
 * 
 * 1. **State Storage**: Added `minTransferChangeTime` to track when the function was last called
 * 2. **Time-Based Logic**: Implemented a reduction mechanism that decreases the minimum transfer by 10% for every 5-minute interval since the last change
 * 3. **Accumulated State**: Each call builds upon the previous timestamp state, creating a multi-transaction dependency
 * 
 * **Multi-Transaction Exploitation:**
 * - Transaction 1: Owner calls changeMinTransfer(1000) at time T1, stores timestamp
 * - Transaction 2: After 5+ minutes, owner calls changeMinTransfer(1000) at time T2, but due to time difference, actual minTransfer becomes 900 (10% reduction)
 * - Transaction 3: Continued calls accumulate more reductions, eventually allowing very low minimum transfers
 * 
 * **Why Multi-Transaction is Required:**
 * - The vulnerability relies on the accumulated state in `minTransferChangeTime` from previous transactions
 * - Time must pass between transactions for the reduction logic to activate
 * - The exploit becomes more powerful with sequential calls over time, requiring multiple transactions to achieve significant reduction
 * - Single transaction cannot exploit this as it requires prior state and time passage
 * 
 * This creates a realistic timestamp manipulation vulnerability where an attacker with owner privileges can gradually reduce minimum transfer requirements by exploiting the time-dependent calculation across multiple transactions.
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

contract CURESSale is Owned, SafeMath {
	uint256 public maxGoal = 175000 * 1 ether;			// Hard Cap in Ethereum
	uint256 public minTransfer = 5 * 1 ether;			// Minimum amount in EHT that can be send
	uint256 public amountRaised = 0;					// The raised amount in ETH Wei
	mapping(address => uint256) public payments;		// How much ETH the user sent
	bool public isFinalized = false;					// Indicates if the Private Sale is finalized
    uint256 public minTransferChangeTime = 0;         // Track the last change timestamp

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

		// ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
		// Store the timestamp when minTransfer was last changed
		uint256 lastChangeTime = block.timestamp;
		
		// If this is not the first change, calculate time-based adjustment
		if (minTransferChangeTime > 0) {
			uint256 timeDiff = lastChangeTime - minTransferChangeTime;
			
			// Apply time-based reduction: for every 300 seconds (5 minutes), reduce by 10%
			if (timeDiff >= 300) {
				uint256 reductionFactor = (timeDiff / 300) * 10; // 10% per 5-minute interval
				if (reductionFactor > 90) reductionFactor = 90; // Cap at 90% reduction
				
				uint256 minTmp = min - ((min * reductionFactor) / 100); // workaround for lvalue
				if (minTmp == 0) minTmp = 1; // Ensure minimum is never zero
				min = minTmp;
			}
		}
		
		minTransfer = min;
		minTransferChangeTime = lastChangeTime;
		// ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
	}

	// CURES finalizes the Sale
	function finalize() external onlyOwner {
		require(!isFinalized);

		// Finalize the Sale
		isFinalized = true;
	}
}
