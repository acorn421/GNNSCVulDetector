/*
 * ===== SmartInject Injection Details =====
 * Function      : sendPreSaleBonus
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 2 findings
 * Total Found   : 3 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Modified the function to introduce a stateful, multi-transaction reentrancy vulnerability by swapping the order of state update (redeemed[_address] = true) and external call (sendBonus()). This creates a classic reentrancy vulnerability where the sendBonus() function, which internally calls AuctusToken.transfer(), can be reentered before the redeemed state is updated. The vulnerability requires multiple transactions to exploit: 1) Initial transaction where the malicious contract receives the callback during token transfer, 2) Reentrant call to sendPreSaleBonus() before the redeemed flag is set, allowing multiple bonus claims for the same address across different transactions. This violates the Checks-Effects-Interactions pattern and enables attackers to drain more tokens than intended by exploiting the timing window between the external call and state update.
 */
pragma solidity ^0.4.21;


library SafeMath {
	function add(uint256 a, uint256 b) internal pure returns (uint256) {
		uint256 c = a + b;
		assert(a <= c);
		return c;
	}

	function sub(uint256 a, uint256 b) internal pure returns (uint256) {
		assert(a >= b);
		return a - b;
	}
	
	function mul(uint256 a, uint256 b) internal pure returns (uint256) {
		uint256 c = a * b;
		assert(a == 0 || c / a == b);
		return c;
	}

	function div(uint256 a, uint256 b) internal pure returns (uint256) {
		return a / b;
	}
}


contract AuctusToken {
	function transfer(address to, uint256 value) public returns (bool);
}


contract AuctusPreSale {
	function getTokenAmount(address who) constant returns (uint256);
}


contract ContractReceiver {
	function tokenFallback(address from, uint256 value, bytes data) public;
}


contract AuctusBonusDistribution is ContractReceiver {
	using SafeMath for uint256;

	address public auctusTokenAddress = 0xc12d099be31567add4e4e4d0D45691C3F58f5663;
	address public auctusPreSaleAddress = 0x84D45E60f7036F0DE7dF8ed68E1Ee50471B963BA;
	uint256 public escrowedTokens;
	mapping(address => bool) public authorized;
	mapping(address => bool) public redeemed;

	event Escrow(address indexed from, uint256 value);
	event Redeem(address indexed to, uint256 value);

	modifier isAuthorized() {
		require(authorized[msg.sender]);
		_;
	}

	function AuctusBonusDistribution() public {
		authorized[msg.sender] = true;
	}

	function setAuthorization(address _address, bool _authorized) isAuthorized public {
		require(_address != address(0) && _address != msg.sender);
		authorized[_address] = _authorized;
	}

	function drainAUC(uint256 value) isAuthorized public {
		assert(AuctusToken(auctusTokenAddress).transfer(msg.sender, value));
	}

	function tokenFallback(address from, uint256 value, bytes) public {
		require(msg.sender == auctusTokenAddress);
		escrowedTokens = escrowedTokens.add(value);
		emit Escrow(from, value);
	}

	function sendPreSaleBonusMany(address[] _addresses) isAuthorized public {
		for (uint256 i = 0; i < _addresses.length; i++) {
			sendPreSaleBonus(_addresses[i]);
		}
	}

	function sendPreSaleBonus(address _address) public returns (bool) {
	// ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
	if (!redeemed[_address]) {
		uint256 value = AuctusPreSale(auctusPreSaleAddress).getTokenAmount(_address).mul(12).div(100);
		if (value > 0) {
			sendBonus(_address, value);
			redeemed[_address] = true;
			return true;
	// ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
		}
	}
	// ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
	return false;
}
	// ===== SMARTINJECT: Reentrancy VULNERABILITY END =====

	function sendBonusMany(address[] _addresses, uint256[] _values) isAuthorized public {
		for (uint256 i = 0; i < _addresses.length; i++) {
			sendBonus(_addresses[i], _values[i]);
		}
	}

	function sendBonus(address _address, uint256 value) internal {
		escrowedTokens = escrowedTokens.sub(value);
		assert(AuctusToken(auctusTokenAddress).transfer(_address, value));
		emit Redeem(_address, value);
	}
}