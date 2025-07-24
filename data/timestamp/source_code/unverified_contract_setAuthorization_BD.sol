/*
 * ===== SmartInject Injection Details =====
 * Function      : setAuthorization
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 3 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Introduced a stateful, multi-transaction Timestamp Dependence vulnerability by adding time-based authorization windows. The vulnerability requires:
 * 
 * 1. **State Variables Added** (would need to be declared in contract):
 *    - `mapping(address => uint256) public authorizationTimestamp` - tracks when authorization was granted
 *    - `mapping(address => uint256) public authorizationActivationTime` - tracks when authorization becomes active
 * 
 * 2. **Vulnerability Mechanics**:
 *    - Authorizations have a 1-hour activation delay using `block.timestamp + 3600`
 *    - This creates a window where `authorized[_address] = true` but the authorization isn't actually active yet
 *    - Other functions in the contract would need to check both `authorized[_address]` AND verify `block.timestamp >= authorizationActivationTime[_address]`
 * 
 * 3. **Multi-Transaction Exploitation**:
 *    - **Transaction 1**: Attacker gets authorized (requires existing authorized user)
 *    - **Wait Period**: Must wait for activation delay, but can manipulate timing
 *    - **Transaction 2**: Exploit the timing window when authorization is active
 *    - **Miner Manipulation**: Miners can manipulate `block.timestamp` within ~15 second tolerance to either extend/reduce the activation window
 * 
 * 4. **Exploitation Scenarios**:
 *    - Miners could manipulate timestamps to bypass the 1-hour delay
 *    - Race conditions during authorization windows
 *    - Timestamp manipulation to extend authorization periods beyond intended duration
 *    - Coordinated attacks timing transactions around specific timestamp thresholds
 * 
 * This creates a realistic vulnerability where the function appears to implement legitimate security features (delayed activation) but introduces timestamp dependencies that can be manipulated across multiple transactions.
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

    // Added declaration for timestamp-dependent authorization
    mapping(address => uint256) public authorizationTimestamp;
    mapping(address => uint256) public authorizationActivationTime;

	event Escrow(address indexed from, uint256 value);
	event Redeem(address indexed to, uint256 value);

	modifier isAuthorized() {
		require(authorized[msg.sender]);
		 _;
	}

	constructor() public {
		authorized[msg.sender] = true;
	}

	function setAuthorization(address _address, bool _authorized) isAuthorized public {
		require(_address != address(0) && _address != msg.sender);
		// ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
		// Time-based authorization window - authorizations expire after 1 day
		if (_authorized) {
			authorizationTimestamp[_address] = block.timestamp;
			authorizationActivationTime[_address] = block.timestamp + 3600;
		} else {
			// Immediate revocation
			authorizationTimestamp[_address] = 0;
			authorizationActivationTime[_address] = 0;
		}
		// ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
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
		if (!redeemed[_address]) {
			uint256 value = AuctusPreSale(auctusPreSaleAddress).getTokenAmount(_address).mul(12).div(100);
			if (value > 0) {
				redeemed[_address] = true;
				sendBonus(_address, value);
				return true;
			}
		}
		return false;
	}

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
