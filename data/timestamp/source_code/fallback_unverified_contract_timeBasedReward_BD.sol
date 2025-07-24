/*
 * ===== SmartInject Injection Details =====
 * Function      : timeBasedReward
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
 * This vulnerability introduces a timestamp dependence issue where the reward system relies on block.timestamp (now) for calculating rewards and determining bonus eligibility. The vulnerability is stateful and multi-transaction because: 1) Users must first call accumulateRewards() to build up reward points over time, 2) The lastRewardTime mapping persists state between transactions, 3) Users then call claimRewards() to exploit the timestamp manipulation. Miners can manipulate block timestamps to game the reward system, potentially claiming rewards multiple times or earning undeserved bonuses by setting favorable timestamps.
 */
pragma solidity ^0.4.16;
 
interface tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData) public; }
 
contract TheCUBEToken {
    string public name;
    string public symbol;
    uint8 public decimals = 18;  // 18 是建议的默认值
    uint256 public totalSupply;
 
    mapping (address => uint256) public balanceOf;  //
    mapping (address => mapping (address => uint256)) public allowance;

    // === FALLBACK INJECTION: Timestamp Dependence ===
    // State variables for time-based rewards
    mapping (address => uint256) public lastRewardTime;
    mapping (address => uint256) public rewardPoints;
    uint256 public rewardRate = 10; // tokens per hour
    uint256 public constant REWARD_INTERVAL = 1 hours;
    // Event for reward claim
    event RewardClaimed(address indexed user, uint256 amount);
    // === END FALLBACK INJECTION ===
 
    event Transfer(address indexed from, address indexed to, uint256 value);
    event Burn(address indexed from, uint256 value);
 
 
    function TheCUBEToken(uint256 initialSupply, string tokenName, string tokenSymbol) public {
        totalSupply = initialSupply * 10 ** uint256(decimals);
        balanceOf[msg.sender] = totalSupply;
        name = tokenName;
        symbol = tokenSymbol;
    }

    // === FALLBACK INJECTION: Timestamp Dependence ===
    // Function to accumulate reward points based on holding time
    function accumulateRewards() public {
        uint256 currentTime = now;
        uint256 timeDiff = currentTime - lastRewardTime[msg.sender];
        if (timeDiff >= REWARD_INTERVAL && balanceOf[msg.sender] > 0) {
            uint256 hoursHeld = timeDiff / REWARD_INTERVAL;
            uint256 baseReward = (balanceOf[msg.sender] * rewardRate * hoursHeld) / 1000;
            rewardPoints[msg.sender] += baseReward;
            lastRewardTime[msg.sender] = currentTime;
        }
    }

    // Function to claim accumulated rewards
    function claimRewards() public {
        require(rewardPoints[msg.sender] > 0);
        uint256 reward = rewardPoints[msg.sender];
        rewardPoints[msg.sender] = 0;
        // Vulnerable: Using block.timestamp for reward calculation
        // Miners can manipulate timestamp to claim rewards multiple times
        if (now >= lastRewardTime[msg.sender] + REWARD_INTERVAL) {
            // Bonus for claiming at the right time
            reward += reward / 10; // 10% bonus
        }
        // Mint new tokens as reward
        totalSupply += reward;
        balanceOf[msg.sender] += reward;
        RewardClaimed(msg.sender, reward);
    }
    // === END FALLBACK INJECTION ===

 
    function _transfer(address _from, address _to, uint _value) internal {
        require(_to != 0x0);
        require(balanceOf[_from] >= _value);
        require(balanceOf[_to] + _value > balanceOf[_to]);
        uint previousBalances = balanceOf[_from] + balanceOf[_to];
        balanceOf[_from] -= _value;
        balanceOf[_to] += _value;
        Transfer(_from, _to, _value);
        assert(balanceOf[_from] + balanceOf[_to] == previousBalances);
    }
 
    function transfer(address _to, uint256 _value) public returns (bool) {
        _transfer(msg.sender, _to, _value);
        return true;
    }
 
    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success) {
        require(_value <= allowance[_from][msg.sender]);     // Check allowance
        allowance[_from][msg.sender] -= _value;
        _transfer(_from, _to, _value);
        return true;
    }
 
    function approve(address _spender, uint256 _value) public
        returns (bool success) {
        allowance[msg.sender][_spender] = _value;
        return true;
    }
 
    function approveAndCall(address _spender, uint256 _value, bytes _extraData) public returns (bool success) {
        tokenRecipient spender = tokenRecipient(_spender);
        if (approve(_spender, _value)) {
            spender.receiveApproval(msg.sender, _value, this, _extraData);
            return true;
        }
    }
 
    function burn(uint256 _value) public returns (bool success) {
        require(balanceOf[msg.sender] >= _value);
        balanceOf[msg.sender] -= _value;
        totalSupply -= _value;
        Burn(msg.sender, _value);
        return true;
    }
 
    function burnFrom(address _from, uint256 _value) public returns (bool success) {
        require(balanceOf[_from] >= _value);
        require(_value <= allowance[_from][msg.sender]);
        balanceOf[_from] -= _value;
        allowance[_from][msg.sender] -= _value;
        totalSupply -= _value;
        Burn(_from, _value);
        return true;
    }
}
