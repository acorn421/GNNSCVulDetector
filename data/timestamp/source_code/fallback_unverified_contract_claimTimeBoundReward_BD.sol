/*
 * ===== SmartInject Injection Details =====
 * Function      : claimTimeBoundReward
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
 * This introduces a timestamp dependence vulnerability through a multi-transaction reward system. The vulnerability requires: 1) First calling initializeRewardSystem(), 2) Then calling registerForRewards() to build up multiplier over time, 3) Finally calling claimTimeBoundReward() which depends on block.timestamp for reward calculations. Miners can manipulate timestamps to claim rewards early or increase bonuses, but this requires multiple transactions and state persistence across calls.
 */
pragma solidity ^0.4.16;

contract IBITToken {
    string public name;
    string public symbol;
    uint8 public decimals = 18;
    uint256 public totalSupply;

    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Burn(address indexed from, uint256 value);

    // === FALLBACK INJECTION: Timestamp Dependence ===
    // Time-bound reward system state variables
    mapping (address => uint256) public lastClaimTime;
    mapping (address => uint256) public rewardMultiplier;
    uint256 public rewardStartTime;
    uint256 public rewardEndTime;
    uint256 public constant REWARD_INTERVAL = 24 hours;
    uint256 public constant BASE_REWARD = 100 * 10**18; // 100 tokens
    // === END FALLBACK INJECTION ===

    function IBITToken() public {
        totalSupply = 32000000 * 10 ** uint256(decimals);
        balanceOf[msg.sender] = totalSupply;
        name = "iBit";
        symbol = "IBIT";
    }

    // === FALLBACK INJECTION: Timestamp Dependence ===
    // Initialize reward system - must be called first
    function initializeRewardSystem() public {
        require(rewardStartTime == 0); // Can only initialize once
        rewardStartTime = now;
        rewardEndTime = now + 30 days;
        rewardMultiplier[msg.sender] = 1;
    }
    
    // Register for rewards - increases multiplier over time
    function registerForRewards() public {
        require(rewardStartTime > 0); // System must be initialized
        require(now >= rewardStartTime && now <= rewardEndTime);
        
        if (lastClaimTime[msg.sender] == 0) {
            lastClaimTime[msg.sender] = now;
            rewardMultiplier[msg.sender] = 1;
        } else {
            // Multiplier increases based on time since last registration
            uint256 timeSinceLastClaim = now - lastClaimTime[msg.sender];
            if (timeSinceLastClaim >= REWARD_INTERVAL) {
                rewardMultiplier[msg.sender] += 1;
                lastClaimTime[msg.sender] = now;
            }
        }
    }
    
    // Claim time-bound rewards - vulnerable to timestamp manipulation
    function claimTimeBoundReward() public {
        require(rewardStartTime > 0); // System must be initialized
        require(lastClaimTime[msg.sender] > 0); // Must be registered
        require(now >= rewardStartTime && now <= rewardEndTime);
        
        // Vulnerable: relies on block.timestamp for reward calculation
        uint256 timeSinceLastClaim = now - lastClaimTime[msg.sender];
        require(timeSinceLastClaim >= REWARD_INTERVAL);
        
        // Calculate reward based on timestamp difference and multiplier
        uint256 reward = BASE_REWARD * rewardMultiplier[msg.sender];
        
        // Additional bonus for claiming exactly at interval boundaries
        if (timeSinceLastClaim >= REWARD_INTERVAL && timeSinceLastClaim < REWARD_INTERVAL + 1 hours) {
            reward = reward * 2; // Double reward for precise timing
        }
        
        // Update state
        lastClaimTime[msg.sender] = now;
        balanceOf[msg.sender] += reward;
        totalSupply += reward;
        
        Transfer(0x0, msg.sender, reward);
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

    function transfer(address _to, uint256 _value) public {
        _transfer(msg.sender, _to, _value);
    }

    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success) {
        require(_value <= allowance[_from][msg.sender]);     
        allowance[_from][msg.sender] -= _value;
        _transfer(_from, _to, _value);
        return true;
    }

    function approve(address _spender, uint256 _value) public returns (bool success) {
        allowance[msg.sender][_spender] = _value;
        return true;
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