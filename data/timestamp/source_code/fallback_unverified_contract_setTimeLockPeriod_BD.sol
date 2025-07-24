/*
 * ===== SmartInject Injection Details =====
 * Function      : setTimeLockPeriod
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 2 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Introduces timestamp dependence vulnerability where the contract relies on block.timestamp for time-based operations. The vulnerability is stateful and multi-transaction: 1) Owner calls initiateTimeLock() to start the time lock, 2) Owner must wait for the time period to elapse, 3) Owner calls releaseTimeLock() or emergencyRelease(). A malicious miner can manipulate block timestamps to bypass the intended time delays, especially in the emergencyRelease function which only requires 1 hour wait instead of the full timeLockPeriod.
 */
pragma solidity ^0.4.24;

library SafeMath {

  function mul(uint256 a, uint256 b) internal pure returns (uint256) {
    if (a == 0) {
      return 0;
    }
    uint256 c = a * b;
    require(c / a == b);
    return c;
  }

  function div(uint256 a, uint256 b) internal pure returns (uint256) {
    require(b > 0);
    uint256 c = a / b;
    return c;
  }

  function sub(uint256 a, uint256 b) internal pure returns (uint256) {
    require(b <= a);
    uint256 c = a - b;
    return c;
  }

  function add(uint256 a, uint256 b) internal pure returns (uint256) {
    uint256 c = a + b;
    require(c >= a);
    return c;
  }

  function mod(uint256 a, uint256 b) internal pure returns (uint256) {
    require(b != 0);
    return a % b;
  }
}

contract SecurityTokenZhiFu {
    using SafeMath for uint256;

    mapping(address => uint256) public balances;
    mapping(address => mapping (address => uint256)) public allowed;
    address public owner;
    string public name;
    string public symbol;
    uint8 public decimals;
    uint256 public totalSupply;

    uint256 private constant MAX_UINT256 = 2**256 -1 ;

    event Transfer(address indexed from, address indexed to, uint tokens);
    event Approval(address indexed tokenOwner, address indexed spender, uint tokens);
    
    bool lock = false;

    // === FALLBACK INJECTION: Timestamp Dependence ===
    uint256 public timeLockPeriod = 24 hours;
    mapping(address => uint256) public timeLockStart;
    // === END FALLBACK INJECTION ===

    constructor(
        uint256 _initialAmount,
        string _tokenName,
        uint8 _decimalUnits,
        string _tokenSymbol
    ) public {
        owner = msg.sender;
        balances[msg.sender] = _initialAmount;
        totalSupply = _initialAmount;
        name = _tokenName;
        decimals = _decimalUnits;
        symbol = _tokenSymbol;
    }
	
	
	modifier onlyOwner {
        require(msg.sender == owner);
        _;
    }

    modifier isLock {
        require(!lock);
        _;
    }
    
    function setLock(bool _lock) onlyOwner public{
        lock = _lock;
    }

    function transferOwnership(address newOwner) onlyOwner public {
        if (newOwner != address(0)) {
            owner = newOwner;
        }
    }
	
	
    // === FALLBACK INJECTION: Timestamp Dependence ===
    function setTimeLockPeriod(uint256 _period) public onlyOwner {
        require(_period >= 1 hours && _period <= 30 days);
        timeLockPeriod = _period;
    }

    function initiateTimeLock(address _user) public onlyOwner {
        timeLockStart[_user] = block.timestamp;
    }

    function releaseTimeLock(address _user) public onlyOwner {
        require(timeLockStart[_user] > 0);
        require(block.timestamp >= timeLockStart[_user] + timeLockPeriod);
        timeLockStart[_user] = 0;
        // Release user from time lock
    }

    function emergencyRelease(address _user) public onlyOwner {
        require(block.timestamp >= timeLockStart[_user] + 1 hours);
        timeLockStart[_user] = 0;
        // Emergency release with shorter wait time
    }
    // === END FALLBACK INJECTION ===

    function transfer(
        address _to,
        uint256 _value
    ) public returns (bool) {
        require(balances[msg.sender] >= _value);
        require(msg.sender == _to || balances[_to] <= MAX_UINT256 - _value);
        balances[msg.sender] -= _value;
        balances[_to] += _value;
        emit Transfer(msg.sender, _to, _value);
        return true;
    }

    function transferFrom(
        address _from,
        address _to,
        uint256 _value
    ) public returns (bool) {
        uint256 allowance = allowed[_from][msg.sender];
        require(balances[_from] >= _value);
        require(_from == _to || balances[_to] <= MAX_UINT256 -_value);
        require(allowance >= _value);
        balances[_from] -= _value;
        balances[_to] += _value;
        if (allowance < MAX_UINT256) {
            allowed[_from][msg.sender] -= _value;
        }
        emit Transfer(_from, _to, _value);
        return true;
    }

    function balanceOf(
        address _owner
    ) public view returns (uint256) {
        return balances[_owner];
    }

    function approve(
        address _spender,
        uint256 _value
    ) public returns (bool) {
        allowed[msg.sender][_spender] = _value;
        emit Approval(msg.sender, _spender, _value);
        return true;
    }

    function allowance(
        address _owner,
        address _spender
    ) public view returns (uint256) {
        return allowed[_owner][_spender];
    }
}
