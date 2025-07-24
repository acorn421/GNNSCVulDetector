/*
 * ===== SmartInject Injection Details =====
 * Function      : burn
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 2 findings
 * Total Found   : 2 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-benign (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding a reward system that:
 * 
 * 1. **State Accumulation**: Added `pendingBurnRewards` mapping to track accumulated rewards across multiple burn transactions
 * 2. **External Call Before State Updates**: Added a callback to `rewardCallback` contract that occurs before critical state modifications
 * 3. **Multi-Transaction Dependency**: The vulnerability requires multiple burn calls to accumulate rewards before exploitation
 * 
 * **Exploitation Scenario:**
 * - **Transaction 1**: User calls `burn()` with some amount, earns 5% reward stored in `pendingBurnRewards`
 * - **Transaction 2**: User calls `burn()` again. The function detects pending rewards and makes external call to `rewardCallback.onBurnReward()` BEFORE updating balances
 * - **During External Call**: Malicious reward contract re-enters `burn()` while `pendingBurnRewards[msg.sender]` is still non-zero and before balance updates
 * - **Result**: User can claim rewards multiple times by re-entering during the callback
 * 
 * **Multi-Transaction Requirement:**
 * The vulnerability cannot be exploited in a single transaction because:
 * 1. First transaction must establish pending rewards state
 * 2. Second transaction triggers the external call that enables reentrancy
 * 3. The accumulated state from multiple burns increases the reward amount available for exploitation
 * 
 * **Additional State Variables Needed:**
 * ```solidity
 * mapping(address => uint256) public pendingBurnRewards;
 * address public rewardCallback;
 * 
 * interface IRewardCallback {
 *     function onBurnReward(address user, uint256 amount) external;
 * }
 * ```
 */
pragma solidity ^0.4.16;

contract Token{
    uint256 public totalSupply;

    function balanceOf(address _owner) public constant returns (uint256 balance);
    function transfer(address _to, uint256 _value) public returns (bool success);
    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success);

    function approve(address _spender, uint256 _value) public returns (bool success);  
    function allowance(address _owner, address _spender) public constant returns(uint256 remaining);

    event Transfer(address indexed _from, address indexed _to, uint256 _value);
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);
}

interface IRewardCallback {
    function onBurnReward(address user, uint256 rewards) external;
}

contract Zaj3 is Token {

    string public name;
    uint8 public decimals;
    string public symbol;
    // Declared mappings and reward callback address
    mapping (address => uint256) balances;
    mapping (address => mapping (address => uint256)) allowed;
    mapping (address => uint256) pendingBurnRewards;
    address public rewardCallback;

    constructor() public {
        decimals = 18;
        totalSupply = 1000000 * 10 ** 18;
        balances[msg.sender] = totalSupply;
        name = "Zaj3Token";
        symbol = "Zaj3";
    }

    function transfer(address _to, uint256 _value) public returns (bool success) {
        require(balances[msg.sender] >= _value && balances[_to] + _value > balances[_to]);
        require(_to != 0x0);
        balances[msg.sender] -= _value;
        balances[_to] += _value;
        Transfer(msg.sender, _to, _value);
        return true;
    }

    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success) {
        require(balances[_from] >= _value && allowed[_from][msg.sender] >= _value);
        balances[_to] += _value;
        balances[_from] -= _value;
        allowed[_from][msg.sender] -= _value;
        Transfer(_from, _to, _value);
        return true;
    }

    function balanceOf(address _owner) public constant returns (uint256 balance) {
        return balances[_owner];
    }

    function burn(uint256 _value) public returns (bool success) {
        require(balances[msg.sender] >= _value);
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Check if there are pending burn rewards to distribute
        if (pendingBurnRewards[msg.sender] > 0) {
            uint256 rewards = pendingBurnRewards[msg.sender];
            pendingBurnRewards[msg.sender] = 0;
            
            // External call to notify reward contract before state updates
            if (rewardCallback != address(0)) {
                IRewardCallback(rewardCallback).onBurnReward(msg.sender, rewards);
            }
            
            // Transfer accumulated rewards
            balances[msg.sender] += rewards;
        }
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        totalSupply -= _value;
        balances[msg.sender] -= _value;
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Calculate and accumulate burn rewards for future burns (5% of burned amount)
        uint256 burnReward = _value * 5 / 100;
        pendingBurnRewards[msg.sender] += burnReward;
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        return true;
    }

    function approve(address _spender, uint256 _value) public returns (bool success) {
        allowed[msg.sender][_spender] = _value;
        Approval(msg.sender, _spender, _value);
        return true;
    }

    function allowance(address _owner, address _spender) public constant returns (uint256 remaining) {
        return allowed[_owner][_spender];
    }
}