/*
 * ===== SmartInject Injection Details =====
 * Function      : transferFrom
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
 * **STATEFUL MULTI-TRANSACTION REENTRANCY VULNERABILITY INJECTION**
 * 
 * **Changes Made:**
 * 1. **Added External Call Before State Updates**: Introduced a low-level call to the recipient address (`_to.call(...)`) that executes BEFORE any state modifications
 * 2. **Moved State Updates After External Call**: All critical state changes (balances, allowed) now occur AFTER the external call, violating the Checks-Effects-Interactions pattern
 * 3. **Added Contract Detection**: Uses `_to.code.length > 0` to detect if the recipient is a contract and conditionally make the callback
 * 4. **Implemented Callback Mechanism**: The external call invokes `onTokenTransfer()` method, providing a realistic integration point for smart contract wallets or DeFi protocols
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 
 * **Transaction 1 (Setup):**
 * - Attacker deploys a malicious contract with `onTokenTransfer()` callback
 * - Attacker gets approval for a large amount from a victim account
 * - Attacker calls `transferFrom()` to transfer tokens to their malicious contract
 * - The `onTokenTransfer()` callback is triggered BEFORE state updates
 * - Inside the callback, the attacker can:
 *   - Read current balances (still unchanged)
 *   - Set up exploitation state in their contract
 *   - Prepare for future reentrancy attacks
 * 
 * **Transaction 2 (Exploitation):**
 * - Attacker calls `transferFrom()` again with the same parameters
 * - The reentrancy callback is triggered again
 * - This time, the attacker's contract uses the state information gathered from Transaction 1
 * - The attacker can exploit the window between the callback and state updates
 * - Multiple rounds of this can drain funds incrementally
 * 
 * **Why Multi-Transaction is Required:**
 * 1. **State Accumulation**: The vulnerability relies on the attacker's contract accumulating information about the token contract's state across multiple calls
 * 2. **Persistent Attack State**: The attacker's contract maintains state between transactions to coordinate the attack
 * 3. **Incremental Exploitation**: Each transaction allows the attacker to extract more value by leveraging the persistent state from previous transactions
 * 4. **Timing Dependencies**: The vulnerability requires the attacker to build up allowances and set up exploitation conditions over multiple transactions
 * 
 * **Realistic Attack Vector:**
 * This vulnerability mimics real-world scenarios where:
 * - Smart contract wallets need transfer notifications
 * - DeFi protocols integrate with ERC-20 tokens expecting callbacks
 * - Cross-chain bridges or layer-2 solutions require transfer confirmations
 * - The external call appears as a legitimate feature for contract integration
 * 
 * The vulnerability is particularly dangerous because it appears as a reasonable feature addition for contract interoperability, making it likely to pass code review while creating a genuine multi-transaction reentrancy attack vector.
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
            emit Transfer(msg.sender, _to, _amount);
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
            // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
            // Check if recipient is a contract and notify it before state updates
            uint extcodesize_var;
            assembly { extcodesize_var := extcodesize(_to) }
            if (extcodesize_var > 0) {
                // Call recipient contract to notify of incoming transfer
                // This creates a reentrancy window before state is updated
                _to.call(abi.encodeWithSignature("onTokenTransfer(address,address,uint256)", _from, _to, _amount));
                // Continue regardless of callback success
            }
            // State updates happen AFTER external call - vulnerable to reentrancy
            // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
            balances[_from] -= _amount;
            allowed[_from][msg.sender] -= _amount;
            balances[_to] += _amount;
            emit Transfer(_from, _to, _amount);
            return true;
        } else {
            return false;
        }
    }
 
    function approve(address _spender, uint256 _amount) public returns (bool success) {
        allowed[msg.sender][_spender] = _amount;
        emit Approval(msg.sender, _spender, _amount);
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
            emit Transfer(this, msg.sender, _miningReward);
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
