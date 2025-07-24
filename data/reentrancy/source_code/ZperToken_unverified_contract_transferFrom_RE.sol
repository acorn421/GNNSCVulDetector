/*
 * ===== SmartInject Injection Details =====
 * Function      : transferFrom
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
 * **VULNERABILITY DETAILS:**
 * 
 * **1. Specific Changes Made:**
 * - Added external call to recipient contract before state updates (violates Checks-Effects-Interactions pattern)
 * - Introduced `_to.code.length > 0` check to identify contract recipients
 * - Added `_to.call(abi.encodeWithSignature("onTokenReceive(address,address,uint256)", _from, _to, _value))` external call
 * - External call happens BEFORE balance and allowance state updates
 * 
 * **2. Multi-Transaction Exploitation Scenario:**
 * 
 * **Transaction 1 (Setup):**
 * - Attacker approves malicious contract to spend tokens via `approve()`
 * - Malicious contract calls `transferFrom()` with itself as `_to`
 * - External call triggers `onTokenReceive()` in malicious contract
 * - Malicious contract can now re-enter `transferFrom()` while original state is unchanged
 * - First call completes, updating balances and allowances
 * 
 * **Transaction 2 (Exploitation):**
 * - Attacker uses state information gathered from Transaction 1
 * - Malicious contract can call `transferFrom()` again with knowledge of:
 *   - Exact timing of state changes
 *   - Intermediate state values
 *   - Allowance values before they were decremented
 * - Can potentially drain tokens by exploiting the timing window
 * 
 * **3. Why Multi-Transaction is Required:**
 * 
 * **State Persistence Requirement:**
 * - The vulnerability relies on the persistent state of `balances` and `allowed` mappings
 * - Between transactions, the malicious contract can analyze the state changes
 * - It can prepare subsequent transactions based on the state information gathered
 * 
 * **Timing-Based Exploitation:**
 * - Transaction 1 establishes the reentrant call pattern and state timing
 * - Transaction 2 exploits the knowledge of when exactly state changes occur
 * - The attacker can coordinate multiple `transferFrom()` calls across transactions
 * 
 * **Allowance Mechanism Exploitation:**
 * - The allowance system requires multiple transactions to be fully exploited
 * - Attacker can manipulate allowance values across multiple calls
 * - Each transaction can partially consume allowances while gaining information
 * 
 * **Real-World Attack Vector:**
 * An attacker could create a contract that:
 * 1. **Transaction 1**: Receives tokens via `transferFrom()`, during `onTokenReceive()` callback gathers state info
 * 2. **Transaction 2**: Uses gathered information to call `transferFrom()` again with precise timing
 * 3. **Transaction 3**: Exploits any remaining allowances or balance inconsistencies
 * 
 * This creates a **stateful, multi-transaction reentrancy** where the vulnerability spans multiple blocks and requires persistent state manipulation to be effective.
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

	event Mint(address indexed to, uint256 amount);
	event Transfer(address indexed _from, address indexed _to, uint256 _value);
	event Approval(address indexed _owner, address indexed _spender, uint256 _value);
	event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);
	event Burn(address indexed burner, uint256 value);

    constructor (address _owner, uint256 _totalSupply, uint256 _cap) public {
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
	// ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
		require(_to != address(0));
		require(balances[_from] >= _value && allowed[_from][msg.sender] >= _value);

		// VULNERABILITY: External call before state updates (violates CEI pattern)
		// This creates a window for reentrancy where state is checked but not yet updated
		uint32 size;
		assembly {
			size := extcodesize(_to)
		}
		if(size > 0) {
			// Call onTokenReceive hook if recipient is a contract
			(bool callSuccess,) = _to.call(abi.encodeWithSignature("onTokenReceive(address,address,uint256)", _from, _to, _value));
			// Continue execution regardless of call success to maintain functionality
		}

		balances[_from] = balances[_from].sub(_value);
		balances[_to] = balances[_to].add(_value);
		allowed[_from][msg.sender] = allowed[_from][msg.sender].sub(_value);

		emit Transfer(_from, _to, _value);
		return true;
	}
	// ===== SMARTINJECT: Reentrancy VULNERABILITY END =====

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

		totalSupply = totalSupply.add(_amount);
		balances[_to] = balances[_to].add(_amount);

		emit Mint(_to, _amount);
		emit Transfer(address(0), _to, _amount);

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
