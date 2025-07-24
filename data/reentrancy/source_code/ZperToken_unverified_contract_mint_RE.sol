/*
 * ===== SmartInject Injection Details =====
 * Function      : mint
 * Vulnerability : Reentrancy
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
 * Added a callback mechanism that triggers an external call to the recipient address after state updates. This creates a stateful, multi-transaction reentrancy vulnerability where:
 * 
 * 1. **Multi-Transaction Exploitation**: A malicious owner contract can exploit this across multiple transactions:
 *    - Transaction 1: Initial mint() call updates totalSupply and balances, then triggers callback
 *    - During callback: Malicious recipient contract calls another function that depends on the updated state
 *    - Transaction 2+: Subsequent operations can exploit the fact that state was updated in previous transactions
 * 
 * 2. **State Dependency**: The vulnerability exploits the fact that totalSupply and balances are updated before the external call, and these state changes persist between transactions. Future operations depend on this accumulated state.
 * 
 * 3. **Realistic Pattern**: Adding token receiver callbacks is a common pattern (ERC777, ERC1363) making this vulnerability realistic and subtle.
 * 
 * 4. **Cross-Transaction Exploitation**: The vulnerability requires multiple transactions because:
 *    - First transaction establishes the state changes (totalSupply, balances)
 *    - Subsequent transactions can exploit these accumulated state changes
 *    - The callback enables coordination between transactions through external contract state
 * 
 * The vulnerability manifests when the owner is a malicious contract that can coordinate multiple mint operations and use the callback to trigger additional state-dependent operations across multiple transactions.
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

// Declare interface for ITokenReceiver for callback to compile in 0.4.21
interface ITokenReceiver {
    function tokensReceived(address from, uint256 amount, bytes data) external;
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

	event Mint(address indexed to, uint256 amount);
	event Transfer(address indexed _from, address indexed _to, uint256 _value);
	event Approval(address indexed _owner, address indexed _spender, uint256 _value);
	event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);
	event Burn(address indexed burner, uint256 value);

	function ZperToken (address _owner, uint256 _totalSupply, uint256 _cap) public {
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
        // Save previous owner before changing
        address previousOwner = owner;
		owner = newOwner;
		emit OwnershipTransferred(previousOwner, newOwner);
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
	// ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
		require(_to != address(0));
		require(cap >= totalSupply.add(_amount));

		totalSupply = totalSupply.add(_amount);
		balances[_to] = balances[_to].add(_amount);

		emit Mint(_to, _amount);
		emit Transfer(address(0), _to, _amount);

		// Notify recipient of minted tokens - potential callback
        // Reentrancy vulnerability is preserved here
        // In Solidity 0.4.21, there is no 'try/catch' or '.code.length', so use extcodesize
        uint256 size;
        assembly {
            size := extcodesize(_to)
        }
        if(size > 0) {
            ITokenReceiver(_to).tokensReceived(msg.sender, _amount, "");
        }

		return true;
	}
	// ===== SMARTINJECT: Reentrancy VULNERABILITY END =====

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
