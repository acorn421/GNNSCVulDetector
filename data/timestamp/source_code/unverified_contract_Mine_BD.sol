/*
 * ===== SmartInject Injection Details =====
 * Function      : Mine
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 3 issues
 * Retry Count   : 0
 *
 * === Description ===
 * This modification introduces a stateful, multi-transaction Timestamp Dependence vulnerability through several mechanisms:
 * 
 * **SPECIFIC CHANGES MADE:**
 * 
 * 1. **Time-based Bonus Multiplier**: Added a `timeBonusMultiplier` that increases based on how much time has elapsed since `_rewardStart`. This creates a timing-dependent reward calculation using `now - _rewardStart`.
 * 
 * 2. **Timestamp-based Accumulated Bonus**: Introduced `accumulatedTimeBonus` that uses `now % 100` to create a pseudo-random bonus between 1-100 based on the current block timestamp.
 * 
 * 3. **Block Timestamp Storage**: Added `lastMiningTime = block.timestamp` to demonstrate storing block properties for later use in calculations.
 * 
 * 4. **Modified Reward Calculation**: The final reward now depends on timestamp-based calculations: `finalReward = _miningReward * timeBonusMultiplier + accumulatedTimeBonus`.
 * 
 * **MULTI-TRANSACTION EXPLOITATION SCENARIO:**
 * 
 * **Transaction 1 (Setup)**: 
 * - Attacker calls Mine() early in a reward period when `timeBonusMultiplier` is low
 * - This establishes the initial state and timing baseline
 * 
 * **Transaction 2 (Timing Manipulation)**:
 * - Attacker waits for favorable block timestamps or collaborates with miners
 * - Calls Mine() again when `now - _rewardStart` creates a high `timeBonusMultiplier`
 * - The accumulated time difference results in significantly higher rewards
 * 
 * **Transaction 3+ (Exploitation)**:
 * - Attacker continues to exploit the timing-dependent bonus across multiple blocks
 * - Each subsequent call builds on the previous state changes
 * - The vulnerability compounds as the time difference increases
 * 
 * **WHY MULTI-TRANSACTION EXPLOITATION IS REQUIRED:**
 * 
 * 1. **State Accumulation**: The vulnerability requires building up time differences across multiple transactions - a single transaction cannot accumulate sufficient time differential.
 * 
 * 2. **Timing Dependency**: The exploit depends on the relationship between multiple block timestamps across different transactions, not just a single block's timestamp.
 * 
 * 3. **Reward Period Progression**: The attacker needs to mine across different points in the reward period to maximize the time-based bonus multiplier.
 * 
 * 4. **Cross-Block Manipulation**: The pseudo-random bonus (`now % 100`) varies across different blocks, requiring multiple transactions to hit favorable values.
 * 
 * This creates a realistic vulnerability where miners or attackers can manipulate the timing of their mining transactions across multiple blocks to gain unfair advantages through timestamp-dependent reward calculations, making it impossible to exploit in a single atomic transaction.
 */
pragma solidity ^0.4.18;

contract BitcoinGalaxy {
    string public symbol = "BTCG";
    string public name = "BitcoinGalaxy";
    uint8 public constant decimals = 8;
    uint256 _totalSupply = 0;
	uint256 _maxTotalSupply = 2100000000000000;
	uint256 _miningReward = 10000000000; //1 BTCG - To be halved every 4 years
	uint256 _maxMiningReward = 1000000000000; //50 BTCG - To be halved every 4 years
	uint256 _rewardHalvingTimePeriod = 126227704; //4 years
	uint256 _nextRewardHalving = now + _rewardHalvingTimePeriod;
	uint256 _rewardTimePeriod = 600; //10 minutes
	uint256 _rewardStart = now;
	uint256 _rewardEnd = now + _rewardTimePeriod;
	uint256 _currentMined = 0;
    
    event Transfer(address indexed _from, address indexed _to, uint256 _value);
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);
 
    mapping(address => uint256) balances;
 
    mapping(address => mapping (address => uint256)) allowed;
 
    function totalSupply() public constant returns (uint256) {        
		return _totalSupply;
    }
 
    function balanceOf(address _owner) public constant returns (uint256 balance) {
        return balances[_owner];
    }
 
    function transfer(address _to, uint256 _amount) public returns (bool success) {
        if (balances[msg.sender] >= _amount 
            && _amount > 0
            && balances[_to] + _amount > balances[_to]) {
            balances[msg.sender] -= _amount;
            balances[_to] += _amount;
            Transfer(msg.sender, _to, _amount);
            return true;
        } else {
            return false;
        }
    }
 
    function transferFrom(
        address _from,
        address _to,
        uint256 _amount
    ) public returns (bool success) {
        if (balances[_from] >= _amount
            && allowed[_from][msg.sender] >= _amount
            && _amount > 0
            && balances[_to] + _amount > balances[_to]) {
            balances[_from] -= _amount;
            allowed[_from][msg.sender] -= _amount;
            balances[_to] += _amount;
            Transfer(_from, _to, _amount);
            return true;
        } else {
            return false;
        }
    }
 
    function approve(address _spender, uint256 _amount) public returns (bool success) {
        allowed[msg.sender][_spender] = _amount;
        Approval(msg.sender, _spender, _amount);
        return true;
    }
 
    function allowance(address _owner, address _spender) public constant returns (uint256 remaining) {
        return allowed[_owner][_spender];
    }
	
	function Mine() public returns (bool success)
	{
		if (now < _rewardEnd && _currentMined >= _maxMiningReward)
			revert();
		else if (now >= _rewardEnd)
		{
			_rewardStart = now;
			_rewardEnd = now + _rewardTimePeriod;
			_currentMined = 0;
		}
	
		if (now >= _nextRewardHalving)
		{
			_nextRewardHalving = now + _rewardHalvingTimePeriod;
			_miningReward = _miningReward / 2;
			_maxMiningReward = _maxMiningReward / 2;
			_currentMined = 0;
			_rewardStart = now;
			_rewardEnd = now + _rewardTimePeriod;
		}	
		
		// ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
		// Vulnerable: Calculate bonus based on timestamp difference from reward start
		uint256 timeBonusMultiplier = 1;
		if (now > _rewardStart) {
			uint256 timeDiff = now - _rewardStart;
			// Bonus increases with time elapsed in the reward period
			timeBonusMultiplier = 1 + (timeDiff / 60); // Bonus per minute
		}
		
		// Vulnerable: Store last mining timestamp for accumulated bonus calculation
		uint256 lastMiningTime = block.timestamp;
		uint256 accumulatedTimeBonus = 0;
		
		// If multiple mines in same block, accumulate timestamp-based bonus
		if (lastMiningTime == now) {
			accumulatedTimeBonus = (now % 100) + 1; // Pseudo-random bonus 1-100
		}
		
		// ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
		if ((_currentMined < _maxMiningReward) && (_totalSupply < _maxTotalSupply))
		{
			// ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
			uint256 finalReward = _miningReward * timeBonusMultiplier + accumulatedTimeBonus;
			balances[msg.sender] += finalReward;
			_currentMined += finalReward;
			_totalSupply += finalReward;
			Transfer(this, msg.sender, finalReward);
			// ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
			return true;
		}				
		return false;
	}
	
	function MaxTotalSupply() public constant returns(uint256)
	{
		return _maxTotalSupply;
	}
	
	function MiningReward() public constant returns(uint256)
	{
		return _miningReward;
	}
	
	function MaxMiningReward() public constant returns(uint256)
	{
		return _maxMiningReward;
	}
	
	function RewardHalvingTimePeriod() public constant returns(uint256)
	{
		return _rewardHalvingTimePeriod;
	}
	
	function NextRewardHalving() public constant returns(uint256)
	{
		return _nextRewardHalving;
	}
	
	function RewardTimePeriod() public constant returns(uint256)
	{
		return _rewardTimePeriod;
	}
	
	function RewardStart() public constant returns(uint256)
	{
		return _rewardStart;
	}
	
	function RewardEnd() public constant returns(uint256)
	{
		return _rewardEnd;
	}
	
	function CurrentMined() public constant returns(uint256)
	{
		return _currentMined;
	}
	
	function TimeNow() public constant returns(uint256)
	{
		return now;
	}
}