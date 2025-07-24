/*
 * ===== SmartInject Injection Details =====
 * Function      : burn
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 1 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Introduced a timestamp-dependent burn rate multiplier system that creates a stateful, multi-transaction vulnerability. The function now uses block.timestamp to determine hourly burn rate multipliers and tracks user burn history. This creates multiple exploit vectors:
 * 
 * 1. **State Setup Requirement**: Users must make an initial burn transaction to set up their lastBurnTimestamp[msg.sender] state before exploiting the vulnerability.
 * 
 * 2. **Timestamp Manipulation Vulnerability**: Miners can manipulate block.timestamp to:
 *    - Target favorable burn rate multiplier periods (2x-3x rates)
 *    - Manipulate time deltas between burns to maximize progressive bonuses
 *    - Exploit the hourly rate calculation by mining blocks with specific timestamps
 * 
 * 3. **Multi-Transaction Exploitation**: The vulnerability requires:
 *    - **Transaction 1**: Initial burn to establish baseline timestamp state
 *    - **Transaction 2+**: Subsequent burns that exploit the timestamp-dependent rate calculations
 *    - **Stateful Nature**: Each transaction modifies persistent state (lastBurnTimestamp, cumulativeBurnAmount) that affects future transactions
 * 
 * 4. **Inconsistent Burn Accounting**: The function burns _value from user balance but effectiveBurnAmount from totalSupply, creating an accounting discrepancy that compounds over multiple transactions.
 * 
 * The vulnerability is realistic as it implements what appears to be a legitimate burn incentive system, but the reliance on block.timestamp for critical rate calculations makes it exploitable by miners across multiple transactions.
 */
pragma solidity ^0.4.21;

library SafeMath {

/**
 * @dev Multiplies two numbers, throws on overflow.
 */
	function mul(uint256 a, uint256 b) internal pure returns (uint256 c) {
		if (a == 0) {
			return 0;
		}
		c = a * b;
		assert(c / a == b);
		return c;
	}

/**
 * @dev Integer division of two numbers, truncating the quotient.
 */
	function div(uint256 a, uint256 b) internal pure returns (uint256) {
		// assert(b > 0); // Solidity automatically throws when dividing by 0
		// uint256 c = a / b;
		// assert(a == b * c + a % b); // There is no case in which this doesn't hold
		return a / b;
	}

/**
 * @dev Subtracts two numbers, throws on overflow (i.e. if subtrahend is greater than minuend).
 */
	function sub(uint256 a, uint256 b) internal pure returns (uint256) {
		assert(b <= a);
		return a - b;
	}

/**
 * @dev Adds two numbers, throws on overflow.
 */
	function add(uint256 a, uint256 b) internal pure returns (uint256 c) {
		c = a + b;
		assert(c >= a);
		return c;
	}
}

contract ZperToken {
	using SafeMath for uint256;

	address public owner;
	uint256 public totalSupply;
	uint256 public cap;
	string public constant name = "ZperToken";
	string public constant symbol = "ZPR";
	uint8 public constant decimals = 18;

	mapping (address => uint256) public balances;
	mapping (address => mapping (address => uint256)) public allowed;

    // Added for burn vulnerability tracking
    mapping (address => uint256) public lastBurnTimestamp;
    mapping (address => uint256) public cumulativeBurnAmount;

	event Mint(address indexed to, uint256 amount);
	event Transfer(address indexed _from, address indexed _to, uint256 _value);
	event Approval(address indexed _owner, address indexed _spender, uint256 _value);
	event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);
	event Burn(address indexed burner, uint256 value);

    // Updated to constructor syntax for >=0.4.21
	constructor(address _owner, uint256 _totalSupply, uint256 _cap) public {
		require(_owner != address(0));
		require(_cap > _totalSupply && _totalSupply > 0);
		
		totalSupply = _totalSupply * (10 ** 18);
		cap = _cap * (10 ** 18);
		owner = _owner;

		balances[owner] = totalSupply;
	}

	modifier onlyOwner() {
		require(msg.sender == owner);
		_;
	}

	function transferOwnership(address newOwner) onlyOwner public {
		require(newOwner != address(0));
        emit OwnershipTransferred(owner, newOwner);
		owner = newOwner;
	}

	function transfer(address _to, uint256 _value) public returns (bool success) {
		require(_to != address(0));
		require(balances[msg.sender] >= _value);

		balances[msg.sender] = balances[msg.sender].sub(_value);
		balances[_to] = balances[_to].add(_value);
		
		emit Transfer(msg.sender, _to, _value);
		return true;
	}

	function transferFrom(address _from, address _to, uint256 _value) public returns (bool success) {
		require(_to != address(0));
		require(balances[_from] >= _value && allowed[_from][msg.sender] >= _value);

		balances[_from] = balances[_from].sub(_value);
		balances[_to] = balances[_to].add(_value);
		allowed[_from][msg.sender] = allowed[_from][msg.sender].sub(_value);

		emit Transfer(_from, _to, _value);
		return true;
	}

	function balanceOf(address _owner) public view returns (uint256 balance) {
		return balances[_owner];
	}

	function approve(address _spender, uint256 _value) public returns (bool success) {
		allowed[msg.sender][_spender] = _value;

		emit Approval(msg.sender, _spender, _value);
		return true;
	}

	function allowance(address _owner, address _spender) public view returns (uint256 remaining) {
		return allowed[_owner][_spender];
	}

	function mint(address _to, uint256 _amount) onlyOwner public returns (bool) {
		require(_to != address(0));
		require(cap >= totalSupply.add(_amount));

		totalSupply = totalSupply.add(_amount);
		balances[_to] = balances[_to].add(_amount);

		emit Mint(_to, _amount);
		emit Transfer(address(0), _to, _amount);

		return true;
	}

	function burn(uint256 _value) public returns (bool) {
		require(_value <= balances[msg.sender]);

		// ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
		// Time-based burn rate multiplier system
		uint256 burnMultiplier = 1;
		uint256 currentHour = (block.timestamp / 3600) % 24;
		
		// Higher burn rates during "off-peak" hours (vulnerable to timestamp manipulation)
		if (currentHour >= 2 && currentHour <= 6) {
			burnMultiplier = 2; // 2x burn rate during early morning hours
		} else if (currentHour >= 14 && currentHour <= 18) {
			burnMultiplier = 3; // 3x burn rate during afternoon hours
		}

		// Track cumulative burn history for rate calculation
		if (lastBurnTimestamp[msg.sender] == 0) {
			lastBurnTimestamp[msg.sender] = block.timestamp;
			cumulativeBurnAmount[msg.sender] = 0;
		}

		// Calculate time-weighted burn amount
		uint256 timeDelta = block.timestamp - lastBurnTimestamp[msg.sender];
		uint256 effectiveBurnAmount = _value;
		
		// Progressive burn bonus based on time since last burn
		if (timeDelta > 86400) { // More than 24 hours
			effectiveBurnAmount = _value.mul(burnMultiplier);
		} else if (timeDelta > 3600) { // More than 1 hour
			effectiveBurnAmount = _value.mul(burnMultiplier).div(2);
		}

		// Update burn tracking state
		lastBurnTimestamp[msg.sender] = block.timestamp;
		cumulativeBurnAmount[msg.sender] = cumulativeBurnAmount[msg.sender].add(effectiveBurnAmount);

		// Apply the burn with the calculated effective amount
		balances[msg.sender] = balances[msg.sender].sub(_value);
		totalSupply = totalSupply.sub(effectiveBurnAmount); // Uses multiplied amount for total supply

		emit Burn(msg.sender, effectiveBurnAmount);
		emit Transfer(msg.sender, address(0), effectiveBurnAmount);
		// ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====

		return true;
	}

	function batchTransfer(address[] _tos, uint256[] _amount) onlyOwner public returns (bool success) {
		require(_tos.length == _amount.length);
		uint256 i;
		uint256 sum = 0;

		for(i = 0; i < _amount.length; i++) {
			sum = sum.add(_amount[i]);
			require(_tos[i] != address(0));
		}

		require(balances[msg.sender] >= sum);

		for(i = 0; i < _tos.length; i++)
			transfer(_tos[i], _amount[i]);

		return true;
	}
}
