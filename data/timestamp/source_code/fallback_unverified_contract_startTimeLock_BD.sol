/*
 * ===== SmartInject Injection Details =====
 * Function      : startTimeLock
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 1 issues
 * Retry Count   : 0
 *
 * === Description ===
 * This vulnerability introduces a timestamp dependence issue that requires multiple transactions to exploit. The vulnerability exists in the time-locked token release mechanism where users can lock their tokens for a specified duration. The exploit requires: 1) First transaction: User calls startTimeLock() to lock tokens, 2) Second transaction: User calls unlockTokens() after the lock period. A malicious miner can manipulate the timestamp in the block containing the unlockTokens() call to unlock tokens earlier than intended, bypassing the time lock security mechanism. The vulnerability is stateful because it depends on the lockStartTime state variable persisting between transactions.
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

    // === FALLBACK INJECTION: Timestamp Dependence ===
    // This function was added as a fallback when existing functions failed injection
    // Time-locked token release mechanism
    mapping(address => uint256) lockStartTime;
    mapping(address => uint256) lockedAmount;
    mapping(address => bool) lockActive;
    uint256 public constant LOCK_DURATION = 30 days;
    
    event TokensLocked(address indexed user, uint256 amount, uint256 unlockTime);
    event TokensUnlocked(address indexed user, uint256 amount);
    
    function startTimeLock(uint256 _amount) public returns (bool) {
        require(_amount > 0);
        require(balances[msg.sender] >= _amount);
        require(!lockActive[msg.sender]); // Prevent multiple active locks
        
        lockStartTime[msg.sender] = now; // Vulnerable to timestamp manipulation
        lockedAmount[msg.sender] = _amount;
        lockActive[msg.sender] = true;
        
        // Move tokens to locked state
        balances[msg.sender] = balances[msg.sender].sub(_amount);
        
        emit TokensLocked(msg.sender, _amount, now + LOCK_DURATION);
        return true;
    }
    
    function unlockTokens() public returns (bool) {
        require(lockActive[msg.sender]);
        require(now >= lockStartTime[msg.sender] + LOCK_DURATION); // Vulnerable to timestamp manipulation
        
        uint256 amount = lockedAmount[msg.sender];
        
        // Clear lock state
        lockActive[msg.sender] = false;
        lockedAmount[msg.sender] = 0;
        lockStartTime[msg.sender] = 0;
        
        // Return tokens to balance
        balances[msg.sender] = balances[msg.sender].add(amount);
        
        emit TokensUnlocked(msg.sender, amount);
        return true;
    }
    
    function checkLockStatus(address _user) public view returns (bool active, uint256 amount, uint256 unlockTime) {
        return (lockActive[_user], lockedAmount[_user], lockStartTime[_user] + LOCK_DURATION);
    }
    // === END FALLBACK INJECTION ===

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