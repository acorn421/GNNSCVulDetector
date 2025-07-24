/*
 * ===== SmartInject Injection Details =====
 * Function      : transfer
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 2 findings
 * Total Found   : 4 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-events (SWC-107)
 *
 * === Description ===
 * This modification introduces a stateful, multi-transaction reentrancy vulnerability by adding an external call to the recipient address before state updates. The vulnerability requires multiple transactions to exploit:
 * 
 * **Changes Made:**
 * 1. Added an external call to `_to.call(sig, msg.sender, _amount)` after balance checks but before state updates
 * 2. The call attempts to notify the recipient contract about incoming tokens via `onTokenReceived` callback
 * 3. State modifications (balance updates) occur AFTER the external call, violating Checks-Effects-Interactions pattern
 * 
 * **Multi-Transaction Exploitation:**
 * 1. **Transaction 1**: Attacker calls `transfer()` with malicious contract as recipient
 * 2. **Transaction 2+**: Malicious contract's `onTokenReceived` callback calls `transfer()` again during execution
 * 3. **State Persistence**: Each reentrant call sees the same initial balance (not yet decremented) and can transfer the same amount repeatedly
 * 4. **Cumulative Effect**: Multiple nested calls drain more tokens than the sender's actual balance
 * 
 * **Why Multi-Transaction Required:**
 * - Each reentrant call creates a new transaction context/stack frame
 * - The vulnerability exploits the time gap between external call and state update across multiple call frames
 * - State changes accumulate across multiple nested function calls
 * - A single atomic transaction cannot exploit this - it requires the callback mechanism to trigger additional transfer calls
 * - The persistent `balances` mapping state enables each subsequent call to see stale balance data
 * 
 * This creates a realistic vulnerability where an attacker must deploy a malicious contract and trigger multiple sequential calls to drain funds beyond their actual balance.
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
            // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
            
            // External call to recipient before state updates (VULNERABILITY)
            if(isContract(_to)) {
                bytes4 sig = bytes4(keccak256("onTokenReceived(address,uint256)"));
                _to.call(sig, msg.sender, _amount);
            }
            
            // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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
    
    // Helper function in Solidity <0.5.0 to determine whether address is contract
    function isContract(address _addr) internal view returns (bool) {
        uint256 length;
        assembly { length := extcodesize(_addr) }
        return (length > 0);
    }
}
