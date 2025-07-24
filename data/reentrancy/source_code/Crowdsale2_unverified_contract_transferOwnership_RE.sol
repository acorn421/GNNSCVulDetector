/*
 * ===== SmartInject Injection Details =====
 * Function      : transferOwnership
 * Vulnerability : Reentrancy
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 4 issues
 * Retry Count   : 0
 *
 * === Description ===
 * This vulnerability creates a stateful, multi-transaction reentrancy attack through a pending ownership transfer mechanism. The attack requires multiple transactions:
 * 
 * **Transaction 1 (Setup)**: Attacker deploys a malicious contract that implements `onOwnershipTransferPending()` callback.
 * 
 * **Transaction 2 (Trigger)**: Current owner calls `transferOwnership(maliciousContract)`. During the external call to `onOwnershipTransferPending()`, the malicious contract can:
 * - Call back into the original contract while `pendingOwner` is set but `owner` hasn't been updated yet
 * - Exploit the intermediate state where both old and new owner have certain privileges
 * - Potentially call other functions that check `pendingOwner` vs `owner` states
 * 
 * **Transaction 3+ (Exploitation)**: The attacker can use the pending state information stored in `pendingOwnershipTransfers` mapping to perform additional attacks across multiple transactions, as this state persists until the transfer completes.
 * 
 * **Why Multi-Transaction**: The vulnerability creates a persistent intermediate state (`pendingOwner` set, `pendingOwnershipTransfers` mapping true) that can be exploited across multiple transactions. The external call creates a reentrancy window where the contract state is inconsistent, and subsequent transactions can exploit this inconsistency. An attacker could also monitor the pending state and perform additional transactions during the transfer window.
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

	// ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
    mapping(address => bool) public pendingOwnershipTransfers;
    address public pendingOwner;

    function transferOwnership(address newOwner) public onlyOwner {
        require(newOwner != address(0));
    
        // Set pending state before external call
        pendingOwner = newOwner;
        pendingOwnershipTransfers[newOwner] = true;
    
        // External call to notify new owner - creates reentrancy window
        /* In Solidity 0.4.x there is no way to check for contract code using .code. Instead, we use extcodesize. */
        uint256 size;
        assembly { size := extcodesize(newOwner) }
        if (size > 0) {
            bool success;
            bytes memory data = abi.encodeWithSignature("onOwnershipTransferPending(address)", owner);
            assembly {
                let ptr := add(data, 32)
                success := call(gas, newOwner, 0, ptr, mload(data), 0, 0)
            }
            require(success);
        }
    
        // Emit event while in pending state
        OwnershipTransferred(owner, newOwner);
    
        // State change happens after external call - vulnerable pattern
        owner = newOwner;
    
        // Clear pending state
        pendingOwnershipTransfers[newOwner] = false;
        pendingOwner = address(0);
    }
    // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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
		endTime = _endTime;
		return true;
	}

	function hasEnded() public view returns (bool) {
		return now > endTime;
	}
}
