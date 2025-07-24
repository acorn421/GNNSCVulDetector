/*
 * ===== SmartInject Injection Details =====
 * Function      : timedTransferReward
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 4 issues
 * Retry Count   : 0
 *
 * === Description ===
 * This vulnerability introduces a timestamp dependence issue where reward accumulation relies on block.timestamp. The vulnerability is stateful and multi-transaction because: 1) Users must first call accumulateReward() to start the reward timer and accumulate rewards over time, 2) The state (lastRewardTime and rewardAccumulated) persists between transactions, 3) Users then call claimRewards() in a separate transaction to collect accumulated rewards. A malicious miner can manipulate block.timestamp to accelerate reward accumulation across multiple transactions, requiring the attacker to control mining and execute multiple function calls over time to exploit the vulnerability fully.
 */
pragma solidity ^0.4.25;

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

contract RCRT {
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
    // State variables for timed rewards (moved here for correct contract-level declaration)
    mapping(address => uint256) public lastRewardTime;
    mapping(address => uint256) public rewardAccumulated;
    uint256 public rewardRate = 100; // tokens per hour
    uint256 public constant REWARD_INTERVAL = 3600; // 1 hour in seconds
    // === END OF MOVED STATE VARIABLES ===

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
    
    // === FALLBACK INJECTION: Timestamp Dependence ===
    // Function to accumulate rewards based on timestamp
    function accumulateReward() public {
        uint256 currentTime = block.timestamp;
        uint256 lastTime = lastRewardTime[msg.sender];
        
        if (lastTime == 0) {
            lastRewardTime[msg.sender] = currentTime;
            return;
        }
        // Vulnerable: relies on block.timestamp which can be manipulated by miners
        uint256 timeElapsed = currentTime - lastTime;
        uint256 intervals = timeElapsed / REWARD_INTERVAL;
        if (intervals > 0) {
            uint256 reward = intervals * rewardRate;
            rewardAccumulated[msg.sender] += reward;
            lastRewardTime[msg.sender] = currentTime;
        }
    }
    // Function to claim accumulated rewards
    function claimRewards() public {
        require(rewardAccumulated[msg.sender] > 0, "No rewards to claim");

        uint256 reward = rewardAccumulated[msg.sender];
        rewardAccumulated[msg.sender] = 0;
        // Mint new tokens as rewards
        totalSupply += reward;
        balances[msg.sender] += reward;
        emit Transfer(address(0), msg.sender, reward);
    }
    // === END FALLBACK INJECTION ===

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