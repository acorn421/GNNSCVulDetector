/*
 * ===== SmartInject Injection Details =====
 * Function      : withdrawReward
 * Vulnerability : Reentrancy
 * Status        : Not Detected
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 0 issues
 * Retry Count   : 0
 *
 * === Description ===
 * This creates a stateful, multi-transaction reentrancy vulnerability. Users must first call claimReward() to accumulate rewards based on their token balance, then call withdrawReward() to extract them. The vulnerability exists because the external call to send ETH happens before the state variables (pendingRewards and rewardWithdrawing) are updated. A malicious contract can exploit this by having its fallback function call withdrawReward() again, allowing multiple withdrawals of the same reward amount. The vulnerability requires: 1) Initial token balance setup, 2) claimReward() call to set pending rewards, 3) withdrawReward() call that can be reentered, making it inherently multi-transaction and stateful.
 */
pragma solidity ^0.4.24;

library SafeMath {
    function mul(uint256 a, uint256 b) internal pure returns (uint256) {
        if (a == 0) {return 0;}
        uint256 c = a * b;
        assert(c / a == b);
        return c;
    }
    function div(uint256 a, uint256 b) internal pure returns (uint256) {
        uint256 c = a / b;
        return c;
    }

    function sub(uint256 a, uint256 b) internal pure returns (uint256) {
        assert(b <= a);
        return a - b;
    }
    function add(uint256 a, uint256 b) internal pure returns (uint256) {
        uint256 c = a + b;
        assert(c >= a);
        return c;
    }
}
contract ERC20{
    function balanceOf(address _owner)public view returns (uint256 balance);
    function transfer(address _to, uint256 _value)public returns (bool success);
    function transferFrom(address _from, address _to, uint256 _value)public returns (bool success);
    function approve(address _spender, uint256 _value)public returns (bool success);
    function allowance(address _owner, address _spender)public view returns (uint256 remaining);
    event Transfer(address indexed _from, address indexed _to, uint256 _value);
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);
}
contract MaxWellToken is ERC20{
    using SafeMath for uint256;
    string public name   = "MaxWellToken";
    string public symbol = "MWT"; 
    uint8 public decimals=18;
    uint256 public totalSupply;
    mapping(address => uint256) balances;
    mapping (address => mapping (address => uint256)) internal allowed;

    // === FALLBACK INJECTION: Reentrancy ===
    // Move injected variables and functions outside the constructor as required by Solidity
    mapping(address => uint256) public pendingRewards;
    mapping(address => bool) public rewardWithdrawing;
    
    function claimReward() public {
        require(balances[msg.sender] >= 1000 * 10**18, "Must hold at least 1000 tokens");
        uint256 reward = balances[msg.sender] / 100; // 1% reward
        pendingRewards[msg.sender] += reward;
        emit RewardClaimed(msg.sender, reward);
    }
    
    function withdrawReward() public {
        require(pendingRewards[msg.sender] > 0, "No pending rewards");
        require(!rewardWithdrawing[msg.sender], "Already withdrawing");
        
        rewardWithdrawing[msg.sender] = true;
        uint256 reward = pendingRewards[msg.sender];
        
        // External call before state update - reentrancy vulnerability
        (bool success, ) = msg.sender.call.value(reward)();
        require(success, "Transfer failed");
        
        // State update after external call - vulnerable to reentrancy
        pendingRewards[msg.sender] = 0;
        rewardWithdrawing[msg.sender] = false;
        
        emit RewardWithdrawn(msg.sender, reward);
    }
    
    event RewardClaimed(address indexed user, uint256 amount);
    event RewardWithdrawn(address indexed user, uint256 amount);
    // === END FALLBACK INJECTION ===

    constructor(uint256 initialSupply)public{
        totalSupply = initialSupply * 10 ** uint256(decimals);
        balances[msg.sender] = totalSupply;
    }
    
    function balanceOf(address _owner)public view returns (uint256 balance){
        return balances[_owner];
    }
    
    function transfer(address _to, uint256 _value)public returns (bool success){
        require(_to != address(0));
        require(_value <= balances[msg.sender]);
        
        balances[msg.sender] = balances[msg.sender].sub(_value);
        balances[_to] = balances[_to].add(_value);
        emit Transfer(msg.sender, _to, _value);
        return true;
    }
     
    function transferFrom(address _from, address _to, uint256 _value)public returns (bool success){
        require(_to != address(0));
        require(_value <= balances[_from]);
        require(_value <= allowed[_from][msg.sender]);
    
        balances[_from] = balances[_from].sub(_value);
        balances[_to] = balances[_to].add(_value);
        allowed[_from][msg.sender] = allowed[_from][msg.sender].sub(_value);
        emit Transfer(_from, _to, _value);
        return true;
    }
    
    function approve(address _spender, uint256 _value)public returns (bool success){
        allowed[msg.sender][_spender] = _value;
        emit Approval(msg.sender, _spender, _value);
        return true; 
    }
    
    function allowance(address _owner, address _spender)public view returns (uint256 remaining){
        return allowed[_owner][_spender];
    }
}
