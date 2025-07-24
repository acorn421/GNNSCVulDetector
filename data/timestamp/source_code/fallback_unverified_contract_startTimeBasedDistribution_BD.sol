/*
 * ===== SmartInject Injection Details =====
 * Function      : startTimeBasedDistribution
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
 * This vulnerability creates a stateful, multi-transaction timestamp dependence issue. The vulnerability requires multiple transactions to exploit: 1) First transaction to establish lastClaimTime state, 2) Second transaction to claim rewards with manipulated timestamps. Miners can manipulate block.timestamp to claim rewards more frequently or for longer periods than intended. The vulnerability is stateful because it depends on the lastClaimTime mapping and distributionActive state that persist between transactions. An attacker would need to: 1) Hold tokens and make an initial claim, 2) Wait or manipulate timestamps, 3) Make subsequent claims with manipulated block.timestamp values to extract more rewards than intended.
 */
pragma solidity ^0.4.11;

contract RepostiX   {

    string public name = "RepostiX";      //  token name
    string public symbol = "REPX";           //  token symbol
    uint256 public decimals = 6;            //  token digit

    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;

    uint256 public totalSupply = 0;
    bool public stopped = false;

    uint256 constant valueFounder = 21000000000000000;
    address owner = 0x0;

    modifier isOwner {
        assert(owner == msg.sender);
        _;
    }

    // === FALLBACK INJECTION: Timestamp Dependence ===
    // This function was added as a fallback when existing functions failed injection
    uint256 public distributionStartTime;
    uint256 public distributionEndTime;
    uint256 public distributionRewardPool;
    mapping(address => uint256) public lastClaimTime;
    mapping(address => uint256) public totalClaimed;
    bool public distributionActive = false;
    
    function startTimeBasedDistribution(uint256 _durationInSeconds, uint256 _rewardPool) isOwner {
        require(!distributionActive);
        require(_rewardPool > 0);
        require(balanceOf[owner] >= _rewardPool);
        
        distributionStartTime = block.timestamp;
        distributionEndTime = block.timestamp + _durationInSeconds;
        distributionRewardPool = _rewardPool;
        distributionActive = true;
        
        // Transfer reward pool to contract for distribution
        balanceOf[owner] -= _rewardPool;
        balanceOf[address(this)] += _rewardPool;
    }
    
    function claimTimeBasedReward() isRunning validAddress returns (bool success) {
        require(distributionActive);
        require(block.timestamp >= distributionStartTime);
        require(block.timestamp <= distributionEndTime);
        require(balanceOf[msg.sender] > 0); // Must hold tokens to claim
        
        uint256 timeSinceLastClaim;
        if (lastClaimTime[msg.sender] == 0) {
            // First claim - calculate from distribution start
            timeSinceLastClaim = block.timestamp - distributionStartTime;
        } else {
            // Subsequent claims - calculate from last claim
            require(block.timestamp > lastClaimTime[msg.sender]);
            timeSinceLastClaim = block.timestamp - lastClaimTime[msg.sender];
        }
        
        // Calculate reward based on time elapsed and token balance
        // Vulnerable: Uses block.timestamp which can be manipulated by miners
        uint256 rewardAmount = (balanceOf[msg.sender] * timeSinceLastClaim) / 86400; // Daily rate
        
        // Ensure we don't exceed the reward pool
        require(rewardAmount <= distributionRewardPool);
        require(rewardAmount > 0);
        
        // Update state
        lastClaimTime[msg.sender] = block.timestamp;
        totalClaimed[msg.sender] += rewardAmount;
        distributionRewardPool -= rewardAmount;
        
        // Transfer reward
        balanceOf[address(this)] -= rewardAmount;
        balanceOf[msg.sender] += rewardAmount;
        
        Transfer(address(this), msg.sender, rewardAmount);
        return true;
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

    function RepostiX(address _addressFounder) {
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
