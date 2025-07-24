/*
 * ===== SmartInject Injection Details =====
 * Function      : tokenFallback
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 2 findings
 * Total Found   : 5 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-benign (SWC-107)
 * 2. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the 'from' address before updating the escrowedTokens state. This creates a classic Checks-Effects-Interactions (CEI) pattern violation where:
 * 
 * 1. **Transaction 1**: Attacker's malicious contract calls tokenFallback with crafted data
 * 2. **During Transaction 1**: The external call to ContractReceiver(from).tokenFallback() allows the attacker to reenter
 * 3. **Reentrancy**: The attacker can call other contract functions (like sendBonus) that depend on the not-yet-updated escrowedTokens state
 * 4. **State Accumulation**: Multiple transactions can manipulate the escrowedTokens state before it's properly updated
 * 
 * The vulnerability is multi-transaction because:
 * - The attacker needs to set up a malicious contract that implements ContractReceiver
 * - The first transaction establishes the reentrancy condition
 * - Subsequent reentrant calls within the same transaction or follow-up transactions can exploit the stale state
 * - The escrowedTokens variable accumulates incorrectly across multiple calls, affecting future bonus distributions
 * 
 * This is realistic because it mimics real-world callback patterns where contracts notify token recipients, but the implementation violates the CEI pattern by placing the external call before the critical state update.
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
	function getTokenAmount(address who) public constant returns (uint256);
}

contract ContractReceiver {
    // Declare variables and event to match usage in function
    address public auctusTokenAddress;
    uint256 public escrowedTokens;
    event Escrow(address indexed from, uint256 value);
    using SafeMath for uint256;

    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
    function tokenFallback(address from, uint256 value, bytes data) public {
        require(msg.sender == auctusTokenAddress);
		// VULNERABLE: External call before state update - enables cross-transaction reentrancy
        if (data.length > 0) {
            ContractReceiver(from).tokenFallback(address(this), value, data);
        }

        escrowedTokens = escrowedTokens.add(value);
        emit Escrow(from, value);
    }
    // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
}

contract AuctusBonusDistribution is ContractReceiver {
    using SafeMath for uint256;

    // Shadow parent variables with specific addresses and events
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
