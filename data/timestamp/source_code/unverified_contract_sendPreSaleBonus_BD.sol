/*
 * ===== SmartInject Injection Details =====
 * Function      : sendPreSaleBonus
 * Vulnerability : Timestamp Dependence
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
 * Introduced a stateful, multi-transaction timestamp dependence vulnerability by adding time-based bonus calculations that use block.timestamp and block.number for critical value determination. The vulnerability requires multiple transactions to exploit effectively:
 * 
 * **Key Modifications:**
 * 1. **Time-based bonus multiplier**: Uses `(block.timestamp / 3600) % 24` to create hourly bonus windows that miners can manipulate
 * 2. **Block-based "lucky" bonuses**: Uses `block.number % 100` to create special bonus conditions that can be targeted
 * 3. **State persistence**: The `redeemed` mapping ensures each address can only claim once, requiring attackers to coordinate timing across multiple addresses/transactions
 * 
 * **Multi-Transaction Exploitation Vector:**
 * 1. **Reconnaissance Phase**: Attacker monitors block timestamps and numbers to identify favorable timing windows
 * 2. **Coordination Phase**: Attacker coordinates with miners or waits for specific timing conditions (hour windows or lucky block numbers)
 * 3. **Exploitation Phase**: Multiple transactions are submitted at optimal times to maximize bonuses for different addresses
 * 4. **State Accumulation**: Each successful claim permanently marks addresses as redeemed, requiring fresh addresses for continued exploitation
 * 
 * **Why Multi-Transaction Required:**
 * - Single addresses can only claim once due to the `redeemed` state check
 * - Optimal timing requires coordination across multiple blocks/timestamps
 * - Maximum exploitation requires targeting multiple favorable time windows
 * - Miners need time to manipulate timestamps within allowed drift periods
 * - The vulnerability compounds across multiple claims rather than being exploitable in one transaction
 * 
 * The vulnerability is realistic as it mimics common patterns where projects offer time-based bonuses, but the implementation relies on manipulable block properties without proper validation or rate limiting.
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
		if (!redeemed[_address]) {
			uint256 value = AuctusPreSale(auctusPreSaleAddress).getTokenAmount(_address).mul(12).div(100);
			if (value > 0) {
				// ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
				// Timestamp-dependent bonus multiplier based on block timing
				uint256 timeMultiplier = 100;
				
				// Special bonus periods based on block timestamp modulo
				// Miners can manipulate timestamp within ~15 second drift to hit favorable periods
				uint256 timeWindow = (block.timestamp / 3600) % 24; // Hour of day (0-23)
				if (timeWindow >= 0 && timeWindow < 6) {
					timeMultiplier = 150; // 50% bonus during "night hours" 
				} else if (timeWindow >= 18 && timeWindow < 24) {
					timeMultiplier = 125; // 25% bonus during "evening hours"
				}
				
				// Additional randomness based on block properties for "lucky" bonuses
				// This creates unpredictable timing windows that can be manipulated
				uint256 blockMod = block.number % 100;
				if (blockMod == 77 || blockMod == 13 || blockMod == 42) {
					timeMultiplier = timeMultiplier.add(200); // Lucky block bonus
				}
				
				// Apply time-dependent multiplier
				value = value.mul(timeMultiplier).div(100);
				
				// ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
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