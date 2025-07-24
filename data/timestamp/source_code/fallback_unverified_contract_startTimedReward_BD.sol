/*
 * ===== SmartInject Injection Details =====
 * Function      : startTimedReward
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 4 issues
 * Retry Count   : 0
 *
 * === Description ===
 * This introduces a timestamp dependence vulnerability where users can start a timed reward and claim it after a delay for bonus tokens. The vulnerability is stateful and requires multiple transactions: 1) startTimedReward() to initiate the reward period, 2) claimTimedReward() after the time delay to receive bonus tokens. The bonus calculation depends on block.timestamp which can be manipulated by miners within certain bounds. State persists between transactions through the mapping variables that track reward start times and amounts.
 */
pragma solidity ^0.4.19;

contract MINTY {
    string public name = 'MINTY';
    string public symbol = 'MINTY';
    uint8 public decimals = 18;
    uint public totalSupply = 10000000000000000000000000;
    uint public minted = totalSupply / 5;
    uint public minReward = 1000000000000000000;
    uint public fee = 700000000000000;
    uint public reducer = 1000;
    uint private randomNumber;
    address public owner;
    uint private ownerBalance;
    
    /* This creates an array with all balances */
    mapping (address => uint256) public balanceOf;
    mapping (address => uint256) public successesOf;
    mapping (address => uint256) public failsOf;
    mapping (address => mapping (address => uint256)) public allowance;

    // === FALLBACK INJECTION: Timestamp Dependence ===
    // This function was added as a fallback when existing functions failed injection
    // Mapping to track timed rewards
    mapping (address => uint256) public timedRewardStart;
    mapping (address => uint256) public timedRewardAmount;
    mapping (address => bool) public timedRewardActive;
    
    // Start a timed reward that can be claimed after a delay
    function startTimedReward(uint256 _amount) external {
        require(balanceOf[msg.sender] >= _amount);
        require(!timedRewardActive[msg.sender]);
        require(_amount >= minReward);
        
        // Set the start time and amount
        timedRewardStart[msg.sender] = block.timestamp;
        timedRewardAmount[msg.sender] = _amount;
        timedRewardActive[msg.sender] = true;
        
        // Transfer tokens to contract for holding
        _transfer(msg.sender, this, _amount);
    }
    
    // Claim the timed reward with bonus after delay
    function claimTimedReward() external {
        require(timedRewardActive[msg.sender]);
        require(block.timestamp >= timedRewardStart[msg.sender] + 1 hours);
        
        uint256 baseAmount = timedRewardAmount[msg.sender];
        // Calculate bonus based on time elapsed (vulnerable to timestamp manipulation)
        uint256 timeElapsed = block.timestamp - timedRewardStart[msg.sender];
        uint256 bonus = (baseAmount * timeElapsed) / (24 hours); // Up to 100% bonus after 24 hours
        
        uint256 totalReward = baseAmount + bonus;
        
        // Reset state
        timedRewardStart[msg.sender] = 0;
        timedRewardAmount[msg.sender] = 0;
        timedRewardActive[msg.sender] = false;
        
        // Transfer reward back with bonus
        _transfer(this, msg.sender, totalReward);
    }
    // === END FALLBACK INJECTION ===
    
    /* This generates a public event on the blockchain that will notify clients */
    event Transfer(address indexed from, address indexed to, uint256 value);
    
    modifier onlyOwner {
        if (msg.sender != owner) revert();
        _;
    }
    
    function transferOwnership(address newOwner) external onlyOwner {
        owner = newOwner;
    }
    
    /* Initializes contract with initial supply tokens to the creator of the contract */
    function MINTY() public {
        owner = msg.sender;
        balanceOf[owner] = minted;
        balanceOf[this] = totalSupply - balanceOf[owner];
    }
    
    /* Internal transfer, only can be called by this contract */
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
    
    /* Send coins */
    function transfer(address _to, uint256 _value) external {
        _transfer(msg.sender, _to, _value);
    }
    
    /* Transfer tokens from other address */
    function transferFrom(address _from, address _to, uint256 _value) external returns (bool success) {
        require(_value <= allowance[_from][msg.sender]);     // Check allowance
        allowance[_from][msg.sender] -= _value;
        _transfer(_from, _to, _value);
        return true;
    }
    
    /* Set allowance for other address */
    function approve(address _spender, uint256 _value) external returns (bool success) {
        allowance[msg.sender][_spender] = _value;
        return true;
    }
    
    function withdrawEther() external onlyOwner {
        owner.transfer(ownerBalance);
        ownerBalance = 0;
    }
    
    function () external payable {
        if (msg.value == fee) {
            randomNumber += block.timestamp + uint(msg.sender);
            uint minedAtBlock = uint(block.blockhash(block.number - 1));
            uint minedHashRel = uint(sha256(minedAtBlock + randomNumber + uint(msg.sender))) % 10000000;
            uint balanceRel = balanceOf[msg.sender] * 1000 / minted;
            if (balanceRel >= 1) {
                if (balanceRel > 255) {
                    balanceRel = 255;
                }
                balanceRel = 2 ** balanceRel;
                balanceRel = 5000000 / balanceRel;
                balanceRel = 5000000 - balanceRel;
                if (minedHashRel < balanceRel) {
                    uint reward = minReward + minedHashRel * 1000 / reducer * 100000000000000;
                    _transfer(this, msg.sender, reward);
                    minted += reward;
                    successesOf[msg.sender]++;
                } else {
                    Transfer(this, msg.sender, 0);
                    failsOf[msg.sender]++;
                }
                ownerBalance += fee;
                reducer++;
            } else {
                revert();
            }
        } else {
            revert();
        }
    }
}
