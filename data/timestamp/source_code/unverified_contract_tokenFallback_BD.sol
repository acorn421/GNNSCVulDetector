/*
 * ===== SmartInject Injection Details =====
 * Function      : tokenFallback
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
 * Introduced timestamp dependence vulnerability through time-based bonus calculations that rely on block.timestamp for critical logic. The vulnerability manifests in multiple ways:
 * 
 * **Specific Changes Made:**
 * 1. Added `currentTime = block.timestamp` for timestamp-dependent calculations
 * 2. Introduced `consecutiveDays` tracking that depends on precise timing between deposits
 * 3. Added time window validation using 23-25 hour range for consecutive day bonuses
 * 4. Implemented bonus multiplier logic that affects the escrowed token amount
 * 5. Made the final escrowed amount dependent on timestamp-based calculations
 * 
 * **Multi-Transaction Exploitation Mechanism:**
 * The vulnerability requires multiple transactions because:
 * - **State Accumulation**: `consecutiveDays` and `lastDepositTime` persist between transactions
 * - **Temporal Dependencies**: Each deposit's bonus depends on the timing relative to previous deposits
 * - **Accumulated Advantage**: Bonus multipliers increase over time with consecutive deposits
 * 
 * **Exploitation Scenario:**
 * 1. **Transaction 1**: Attacker makes initial deposit, setting `lastDepositTime`
 * 2. **Timestamp Manipulation**: Miner/attacker influences block timestamps between transactions
 * 3. **Transaction 2+**: Subsequent deposits exploit the manipulated timing to:
 *    - Maximize consecutive day bonuses by maintaining exactly 24-hour intervals
 *    - Exploit the 23-25 hour window to maintain streaks even with timing manipulation
 *    - Accumulate higher bonus multipliers through artificial consecutive day counts
 * 
 * **Why Multi-Transaction Dependence is Critical:**
 * - Single transaction cannot exploit the vulnerability as it requires existing state from previous deposits
 * - The bonus calculation depends on historical timestamp data stored in contract state
 * - Attackers must strategically time multiple deposits to maximize bonus accumulation
 * - The vulnerability's impact compounds over multiple transactions, making it undetectable in isolated calls
 * 
 * This creates a realistic timestamp dependence vulnerability that miners or sophisticated attackers could exploit through strategic transaction timing across multiple blocks.
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
    using SafeMath for uint256;

    address public auctusTokenAddress = 0xc12d099be31567add4e4e4d0D45691C3F58f5663;
    uint256 public escrowedTokens;
    uint256 public lastDepositTime;
    uint256 public consecutiveDays;
    event Escrow(address indexed from, uint256 value);

    function tokenFallback(address from, uint256 value, bytes) public {
        require(msg.sender == auctusTokenAddress);
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        // Time-based bonus calculation - vulnerable to timestamp manipulation
        uint256 bonusMultiplier = 100; // Base 100% (no bonus)
        uint256 currentTime = block.timestamp;
        // Early bird bonus periods based on timestamp
        if (currentTime < lastDepositTime + 1 days) {
            // Consecutive day bonus - increases with each day
            bonusMultiplier = bonusMultiplier.add(consecutiveDays.mul(5)); // 5% per consecutive day
        } else {
            consecutiveDays = 0; // Reset streak if gap > 1 day
        }
        // Update consecutive days and last deposit time
        if (currentTime >= lastDepositTime + 23 hours && currentTime < lastDepositTime + 25 hours) {
            consecutiveDays = consecutiveDays.add(1);
        }
        lastDepositTime = currentTime;
        // Apply time-based bonus to escrowed amount
        uint256 bonusAdjustedValue = value.mul(bonusMultiplier).div(100);
        escrowedTokens = escrowedTokens.add(bonusAdjustedValue);
        emit Escrow(from, bonusAdjustedValue);
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
    }
}

contract AuctusBonusDistribution is ContractReceiver {
	using SafeMath for uint256;

	address public auctusPreSaleAddress = 0x84D45E60f7036F0DE7dF8ed68E1Ee50471B963BA;
	mapping(address => bool) public authorized;
	mapping(address => bool) public redeemed;

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
