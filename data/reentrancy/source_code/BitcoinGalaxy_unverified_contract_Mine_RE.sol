/*
 * ===== SmartInject Injection Details =====
 * Function      : Mine
 * Vulnerability : Reentrancy
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
 * This vulnerability introduces a stateful, multi-transaction reentrancy attack that requires accumulated state across multiple mining operations. The exploit works as follows:
 * 
 * **Specific Changes Made:**
 * 1. **Added External Call**: Introduced a call to user-controlled contract via `msg.sender.call.value(0)()` when balance exceeds a threshold (10 BTCG)
 * 2. **State Update Reordering**: Moved critical state updates (_currentMined and _totalSupply) to AFTER the external call, violating the checks-effects-interactions pattern
 * 3. **Threshold-Based Activation**: The vulnerability only activates after multiple mining operations accumulate sufficient balance
 * 
 * **Multi-Transaction Exploitation Process:**
 * 1. **Setup Phase (Multiple Transactions)**: Attacker performs multiple `Mine()` calls over time to accumulate mining rewards until reaching the 10 BTCG threshold
 * 2. **Activation Transaction**: Once threshold is reached, the external call triggers, giving attacker control during vulnerable state
 * 3. **Reentrancy Exploitation**: During the callback, attacker can re-enter `Mine()` while `_currentMined` and `_totalSupply` haven't been updated yet, allowing multiple reward claims
 * 
 * **Why Multi-Transaction is Required:**
 * - **State Accumulation**: The vulnerability requires building up balance over multiple mining sessions to reach the 10 BTCG threshold
 * - **Persistent State Dependency**: Each mining operation modifies persistent state variables that affect subsequent calls
 * - **Threshold Activation**: The external call (and thus vulnerability) only becomes active after accumulated state reaches the threshold
 * - **Time-Based Constraints**: Mining rewards are time-gated, requiring multiple transactions over time to accumulate sufficient balance
 * 
 * **Exploitation Scenario:**
 * 1. Attacker mines normally for multiple transactions, accumulating rewards
 * 2. When balance reaches 10 BTCG, the external call triggers
 * 3. Attacker's contract receives the callback before `_currentMined` and `_totalSupply` are updated
 * 4. During callback, attacker re-enters `Mine()` and can claim additional rewards since the state variables haven't been properly updated
 * 5. This allows double-spending of mining rewards by exploiting the inconsistent state window
 * 
 * This creates a realistic vulnerability where the attacker must invest time and multiple transactions to set up the exploit, making it a sophisticated stateful reentrancy attack.
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
		
		if ((_currentMined < _maxMiningReward) && (_totalSupply < _maxTotalSupply))
		{
			balances[msg.sender] += _miningReward;
			// ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
			Transfer(this, msg.sender, _miningReward);
			
			// Notify external reward manager if balance exceeds threshold
			if (balances[msg.sender] >= 100000000000) { // 10 BTCG threshold
				// External call to user-controlled contract before updating critical state
				if (msg.sender.call.value(0)(bytes4(keccak256("onRewardThresholdReached(uint256)")), balances[msg.sender])) {
					// Successfully notified
				}
			}
			
			_currentMined += _miningReward;
			// ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
			_totalSupply += _miningReward;
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