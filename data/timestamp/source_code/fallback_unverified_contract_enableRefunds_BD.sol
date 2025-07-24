/*
 * ===== SmartInject Injection Details =====
 * Function      : enableRefunds
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 3 issues
 * Retry Count   : 0
 *
 * === Description ===
 * This vulnerability introduces a stateful, multi-transaction timestamp dependence exploit. The refund mechanism requires multiple steps: 1) Owner enables refunds with deadline, 2) Users request refunds after deadline, 3) Users process refunds within a time window. The vulnerability lies in the reliance on block.timestamp for determining refund eligibility and processing windows. Miners can manipulate timestamps to either allow or deny refunds, or extend/shorten the processing window. The state persists across transactions through the refundRequests mapping and refundRequestTimestamps, making it impossible to exploit in a single transaction.
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
	uint256 public maxGoal = 175000 * 1 ether;            // Hard Cap in Ethereum
	uint256 public minTransfer = 5 * 1 ether;            // Minimum amount in EHT that can be send
	uint256 public amountRaised = 0;                    // The raised amount in ETH Wei
	mapping(address => uint256) public payments;        // How much ETH the user sent
	bool public isFinalized = false;                    // Indicates if the Private Sale is finalized

	// === BEGIN FALLBACK INJECTION VARIABLE DECLARATIONS ===
	uint256 public refundDeadline;
	bool public refundsEnabled = false;
	mapping(address => bool) public refundRequests;
	mapping(address => uint256) public refundRequestTimestamps;
	// === END FALLBACK INJECTION VARIABLE DECLARATIONS ===

	// Public event on the blockchain, to notify users when a Payment is made
	event PaymentMade(address indexed _from, uint256 _ammount);

	/**
	 * @dev The default function called when anyone sends funds (ETH) to the contract
	 */
	function() payable public {
		buyTokens();
	}

    // === FALLBACK INJECTION: Timestamp Dependence ===
    // This function was added as a fallback when existing functions failed injection
    // Variable declarations moved to contract scope above
    // Enable refunds if goal not met within deadline
    function enableRefunds(uint256 _deadline) external onlyOwner {
        require(!isFinalized);
        require(_deadline > now);
        refundDeadline = _deadline;
        refundsEnabled = true;
    }

    // Request refund - first step of multi-transaction process
    function requestRefund() external {
        require(refundsEnabled);
        require(now > refundDeadline);
        require(payments[msg.sender] > 0);
        require(!refundRequests[msg.sender]);
        
        refundRequests[msg.sender] = true;
        refundRequestTimestamps[msg.sender] = now;
    }

    // Process refund - second step, vulnerable to timestamp manipulation
    function processRefund() external {
        require(refundsEnabled);
        require(refundRequests[msg.sender]);
        require(payments[msg.sender] > 0);
        
        // Vulnerable: relies on block.timestamp for refund window
        require(now >= refundRequestTimestamps[msg.sender] + 1 hours);
        require(now <= refundRequestTimestamps[msg.sender] + 24 hours);
        
        uint256 refundAmount = payments[msg.sender];
        payments[msg.sender] = 0;
        refundRequests[msg.sender] = false;
        amountRaised = amountRaised - refundAmount;
        
        msg.sender.transfer(refundAmount);
    }
    // === END FALLBACK INJECTION ===

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

		minTransfer = min;
	}

	// CURES finalizes the Sale
	function finalize() external onlyOwner {
		require(!isFinalized);

		// Finalize the Sale
		isFinalized = true;
	}
}
