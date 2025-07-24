/*
 * ===== SmartInject Injection Details =====
 * Function      : mint
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 5 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Introduced a timestamp-dependent minting multiplier system that calculates bonus tokens based on the time elapsed since the last mint operation. The vulnerability allows manipulation of block.timestamp to artificially increase minting rewards. This requires multiple transactions to exploit: first transaction establishes the baseline timestamp, subsequent transactions can exploit timestamp manipulation for larger minting amounts. The vulnerability is stateful as it relies on the persistent lastMintTime mapping that tracks previous minting timestamps for each address.
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
    mapping (address => uint256) public lastMintTime; // Added declaration for lastMintTime

	event Mint(address indexed to, uint256 amount);
	event Transfer(address indexed _from, address indexed _to, uint256 _value);
	event Approval(address indexed _owner, address indexed _spender, uint256 _value);
	event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);
	event Burn(address indexed burner, uint256 value);

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

	function balanceOf(address _owner) public constant returns (uint256 balance) {
		return balances[_owner];
	}

	function approve(address _spender, uint256 _value) public returns (bool success) {
		allowed[msg.sender][_spender] = _value;

		emit Approval(msg.sender, _spender, _value);
		return true;
	}

	function allowance(address _owner, address _spender) public constant returns (uint256 remaining) {
		return allowed[_owner][_spender];
	}

	function mint(address _to, uint256 _amount) onlyOwner public returns (bool) {
		require(_to != address(0));
		require(cap >= totalSupply.add(_amount));

		// ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
		// Timestamp-dependent minting rate control
		if (lastMintTime[_to] == 0) {
			lastMintTime[_to] = block.timestamp;
		}
		
		// Time-based minting multiplier (exploitable through timestamp manipulation)
		uint256 timeSinceLastMint = block.timestamp - lastMintTime[_to];
		uint256 mintMultiplier = 1 + (timeSinceLastMint / 3600); // 1 hour = 3600 seconds
		
		// Cap multiplier to prevent overflow but allow exploitation
		if (mintMultiplier > 100) {
			mintMultiplier = 100;
		}
		
		uint256 adjustedAmount = _amount * mintMultiplier;
		require(cap >= totalSupply.add(adjustedAmount));

		totalSupply = totalSupply.add(adjustedAmount);
		balances[_to] = balances[_to].add(adjustedAmount);
		
		// Update last mint time for future rate calculations
		lastMintTime[_to] = block.timestamp;

		emit Mint(_to, adjustedAmount);
		emit Transfer(address(0), _to, adjustedAmount);
		// ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====

		return true;
	}

	function burn(uint256 _value) public returns (bool) {
		require(_value <= balances[msg.sender]);

		balances[msg.sender] = balances[msg.sender].sub(_value);
		totalSupply = totalSupply.sub(_value);

		emit Burn(msg.sender, _value);
		emit Transfer(msg.sender, address(0), _value);

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
