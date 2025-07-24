/*
 * ===== SmartInject Injection Details =====
 * Function      : withdrawRewards
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 5 issues
 * Retry Count   : 0
 *
 * === Description ===
 * This vulnerability introduces a timestamp dependence issue where reward calculations rely on block.timestamp (now). The vulnerability is stateful and multi-transaction: users must first call updateRewards() to accumulate rewards over time, then call withdrawRewards() to claim them. Miners can manipulate timestamps to either accelerate reward accumulation or prevent others from claiming rewards at expected times. The state persists between transactions through lastRewardClaim and accumulatedRewards mappings.
 */
pragma solidity ^0.4.11;

contract MycoinToken {

    string public name = "Mycoin";      //  token name
    string public symbol = "MYC";           //  token symbol
    uint256 public decimals = 6;            //  token digit

    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;

    uint256 public totalSupply = 0;
    bool public stopped = false;

    uint256 constant valueFounder = 2100000000000000;
    address owner = 0x0;

    modifier isOwner {
        assert(owner == msg.sender);
        _;
    }

    // === FALLBACK INJECTION: Timestamp Dependence ===
    // This function was added as a fallback when existing functions failed injection
    mapping (address => uint256) public lastRewardClaim;
    mapping (address => uint256) public accumulatedRewards;
    uint256 public rewardRate = 100; // tokens per day
    uint256 public constant REWARD_INTERVAL = 1 days;
    
    function updateRewards() public isRunning validAddress {
        if (lastRewardClaim[msg.sender] == 0) {
            lastRewardClaim[msg.sender] = now;
            return;
        }
        
        uint256 timeSinceLastClaim = now - lastRewardClaim[msg.sender];
        if (timeSinceLastClaim >= REWARD_INTERVAL) {
            uint256 reward = (timeSinceLastClaim / REWARD_INTERVAL) * rewardRate;
            accumulatedRewards[msg.sender] += reward;
            lastRewardClaim[msg.sender] = now;
        }
    }
    
    function withdrawRewards() public isRunning validAddress {
        updateRewards();
        uint256 reward = accumulatedRewards[msg.sender];
        require(reward > 0);
        
        accumulatedRewards[msg.sender] = 0;
        totalSupply += reward;
        balanceOf[msg.sender] += reward;
        Transfer(0x0, msg.sender, reward);
    }
    // === END FALLBACK INJECTION ===

    modifier isRunning {
        assert (!stopped);
        _;
    }

    modifier validAddress {
        assert(0x0 != msg.sender);
        _;
    }

    function MycoinToken(address _addressFounder) {
        owner = msg.sender;
        totalSupply = valueFounder;
        balanceOf[_addressFounder] = valueFounder;
        Transfer(0x0, _addressFounder, valueFounder);
    }

    function transfer(address _to, uint256 _value) isRunning validAddress returns (bool success) {
        require(balanceOf[msg.sender] >= _value);
        require(balanceOf[_to] + _value >= balanceOf[_to]);
        balanceOf[msg.sender] -= _value;
        balanceOf[_to] += _value;
        Transfer(msg.sender, _to, _value);
        return true;
    }

    function transferFrom(address _from, address _to, uint256 _value) isRunning validAddress returns (bool success) {
        require(balanceOf[_from] >= _value);
        require(balanceOf[_to] + _value >= balanceOf[_to]);
        require(allowance[_from][msg.sender] >= _value);
        balanceOf[_to] += _value;
        balanceOf[_from] -= _value;
        allowance[_from][msg.sender] -= _value;
        Transfer(_from, _to, _value);
        return true;
    }

    function approve(address _spender, uint256 _value) isRunning validAddress returns (bool success) {
        require(_value == 0 || allowance[msg.sender][_spender] == 0);
        allowance[msg.sender][_spender] = _value;
        Approval(msg.sender, _spender, _value);
        return true;
    }

    function stop() isOwner {
        stopped = true;
    }

    function start() isOwner {
        stopped = false;
    }

    function setName(string _name) isOwner {
        name = _name;
    }

    function burn(uint256 _value) {
        require(balanceOf[msg.sender] >= _value);
        balanceOf[msg.sender] -= _value;
        balanceOf[0x0] += _value;
        Transfer(msg.sender, 0x0, _value);
    }

    event Transfer(address indexed _from, address indexed _to, uint256 _value);
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);
}
