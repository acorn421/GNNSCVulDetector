/*
 * ===== SmartInject Injection Details =====
 * Function      : StartTimedMining
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 3 issues
 * Retry Count   : 0
 *
 * === Description ===
 * This vulnerability introduces a multi-transaction timestamp dependence attack where miners can manipulate block timestamps to extend profitable mining periods. The vulnerability requires: 1) First transaction to call StartTimedMining() to activate the timed mining period, 2) Multiple transactions calling TimedMine() during the period to accumulate rewards, 3) Miners can manipulate timestamps to extend the mining window beyond intended duration. The state persists across transactions through _timedMiningActive, _timedMiningStart, and _timedMiningDuration variables.
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

    // === FALLBACK INJECTION: Timestamp Dependence ===
    // This function was added as a fallback when existing functions failed injection
    uint256 _timedMiningStart = 0;
    uint256 _timedMiningDuration = 0;
    uint256 _timedMiningBonus = 0;
    bool _timedMiningActive = false;
    // === END FALLBACK INJECTION ===
    
    event Transfer(address indexed _from, address indexed _to, uint256 _value);
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);
 
    mapping(address => uint256) balances;
 
    mapping(address => mapping (address => uint256)) allowed;
 
    function totalSupply() public constant returns (uint256) {        
        return _totalSupply;
    }
    
    // === FALLBACK INJECTION: Timestamp Dependence ===
    // Vulnerable code (preserved)
    function StartTimedMining(uint256 duration, uint256 bonus) public returns (bool success) {
        if (_timedMiningActive) {
            return false;
        }
        _timedMiningStart = now;
        _timedMiningDuration = duration;
        _timedMiningBonus = bonus;
        _timedMiningActive = true;
        return true;
    }

    function TimedMine() public returns (bool success) {
        if (!_timedMiningActive) {
            return false;
        }
        // Vulnerable: Uses block.timestamp for critical timing logic
        if (now <= _timedMiningStart + _timedMiningDuration) {
            uint256 reward = _miningReward + _timedMiningBonus;
            if (_totalSupply + reward <= _maxTotalSupply) {
                balances[msg.sender] += reward;
                _totalSupply += reward;
                Transfer(this, msg.sender, reward);
                return true;
            }
        } else {
            _timedMiningActive = false;
        }
        return false;
    }

    function EndTimedMining() public returns (bool success) {
        if (!_timedMiningActive) {
            return false;
        }
        // Vulnerable: Miners can manipulate timestamp to extend mining period
        if (now >= _timedMiningStart + _timedMiningDuration) {
            _timedMiningActive = false;
            return true;
        }
        return false;
    }
    // === END FALLBACK INJECTION ===

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
            _currentMined += _miningReward;
            _totalSupply += _miningReward;
            Transfer(this, msg.sender, _miningReward);
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