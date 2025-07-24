/*
 * ===== SmartInject Injection Details =====
 * Function      : createTimeLockReward
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 1 issues
 * Retry Count   : 0
 *
 * === Description ===
 * This vulnerability introduces timestamp dependence in a multi-transaction time-locked reward system. The exploit requires: 1) First transaction: createTimeLockReward() to set up a time-locked reward with block.timestamp, 2) Second transaction: claimTimeLockReward() which relies on block.timestamp for validation. Miners can manipulate block.timestamp within ~900 seconds to either delay or accelerate reward claims, allowing them to exploit the timing mechanism across multiple transactions. The state persists between transactions through the timeLockRewards mapping and TimeLockReward struct.
 */
pragma solidity ^0.4.4;
contract SafeMath {
    
    // Multiplication
    function safeMul(uint256 a, uint256 b) internal pure returns (uint256) { 
        uint256 c = a * b;
        assert(a == 0 || c / a == b);
        return c;
    }
  
    // Division
    function safeDiv(uint256 a, uint256 b) internal pure returns (uint256) {
        assert(b > 0);
        uint256 c = a / b;
        assert(a == b * c + a % b);
        return c;
    }
 
    // Subtraction
    function safeSub(uint256 a, uint256 b) internal pure returns (uint256) {
        assert(b <= a);
        assert(b >=0);
        return a - b;
    }
 
    // Addition
    function safeAdd(uint256 a, uint256 b) internal pure returns (uint256) {
        uint256 c = a + b;
        assert(c>=a && c>=b);
        return c;
    }
}
 
contract BTC3xS is SafeMath{
    // Token name
    string public name; 
    // Token symbol
    string public symbol;
    // Token decimals
    uint8 public decimals;
    // Total supply
    uint256 public totalSupply;
    // Owner of contract
    address public owner;
 
    // Balance mapping
    mapping (address => uint256) public balanceOf;
    // Allowance mapping
    mapping (address => mapping (address => uint256)) public allowance;
    // Frozen tokens mapping
    mapping (address => uint256) public freezeOf;

    // === FALLBACK INJECTION: Timestamp Dependence ===
    // Declare the struct and variables at contract scope -- FIXED
    struct TimeLockReward {
        uint256 amount;
        uint256 unlockTime;
        bool claimed;
    }
    mapping(address => TimeLockReward[]) public timeLockRewards;
    mapping(address => uint256) public lastRewardCreation;
    // === END FALLBACK INJECTION ===
    
    // Events
    event Transfer(address indexed from, address indexed to, uint256 value);
    event Burn(address indexed from, uint256 value);
    event Freeze(address indexed from, uint256 value);
    event Unfreeze(address indexed from, uint256 value);
 
    // Constructor
    function BTC3xS( 
        uint256 initialSupply,  // Initial supply
        string tokenName,       // Token name
        uint8 decimalUnits,     // Decimals
        string tokenSymbol      // Symbol
    ) public {
        decimals = decimalUnits;                           
        balanceOf[msg.sender] = initialSupply * 10 ** 18;    
        totalSupply = initialSupply * 10 ** 18;   
        name = tokenName;      
        symbol = tokenSymbol;
        owner = msg.sender;
    }

    // Create a time-locked reward that can be claimed after specified duration
    function createTimeLockReward(address _beneficiary, uint256 _amount, uint256 _lockDuration) public returns (bool success) {
        assert(_beneficiary != 0x0);
        assert(_amount > 0);
        assert(_lockDuration > 0);
        assert(balanceOf[msg.sender] >= _amount);
        balanceOf[msg.sender] = SafeMath.safeSub(balanceOf[msg.sender], _amount);
        uint256 unlockTime = block.timestamp + _lockDuration; // vulnerable
        TimeLockReward memory newReward = TimeLockReward({
            amount: _amount,
            unlockTime: unlockTime,
            claimed: false
        });
        timeLockRewards[_beneficiary].push(newReward);
        lastRewardCreation[_beneficiary] = block.timestamp;
        return true;
    }
    // Claim available time-locked rewards
    function claimTimeLockReward(uint256 _rewardIndex) public returns (bool success) {
        assert(_rewardIndex < timeLockRewards[msg.sender].length);
        TimeLockReward storage reward = timeLockRewards[msg.sender][_rewardIndex];
        assert(!reward.claimed);
        assert(reward.amount > 0);
        assert(block.timestamp >= reward.unlockTime);
        reward.claimed = true;
        balanceOf[msg.sender] = SafeMath.safeAdd(balanceOf[msg.sender], reward.amount);
        return true;
    }
    // Get number of time-locked rewards for an address
    function getTimeLockRewardCount(address _beneficiary) public view returns (uint256) {
        return timeLockRewards[_beneficiary].length;
    }
 
    // Mint new tokens
    function mintToken(address _to, uint256 _value) public returns (bool success){
        assert(_to != 0x0);                       
        assert(_value > 0);
        balanceOf[_to] += _value;
        totalSupply += _value;
        emit Transfer(0, msg.sender, _value);
        emit Transfer(msg.sender, _to, _value);
        return true;
    }
 
    // Transfer tokens
    function transfer(address _to, uint256 _value) public {
        assert(_to != 0x0);                      
        assert(_value > 0);
        assert(balanceOf[msg.sender] >= _value);
        assert(balanceOf[_to] + _value >= balanceOf[_to]);
        balanceOf[msg.sender] = SafeMath.safeSub(balanceOf[msg.sender], _value);     
        balanceOf[_to] = SafeMath.safeAdd(balanceOf[_to], _value); 
        emit Transfer(msg.sender, _to, _value);
    }
 
    // Approve tokens
    function approve(address _spender, uint256 _value) public returns (bool success) {
        assert(_value > 0);
        allowance[msg.sender][_spender] = _value;
        return true;
    }
 
    // Transfer tokens from
    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success) {
        assert(_to != 0x0);
        assert(_value > 0);
        assert(balanceOf[_from] >= _value);
        assert(balanceOf[_to] + _value >= balanceOf[_to]);
        assert(_value <= allowance[_from][msg.sender]);
        balanceOf[_from] = SafeMath.safeSub(balanceOf[_from], _value); 
        balanceOf[_to] = SafeMath.safeAdd(balanceOf[_to], _value); 
        allowance[_from][msg.sender] = SafeMath.safeSub(allowance[_from][msg.sender], _value);
        emit Transfer(_from, _to, _value);
        return true;
    }
 
    // Burn tokens
    function burn(uint256 _value) public returns (bool success) {
        assert(balanceOf[msg.sender] >= _value);
        assert(_value > 0);
        balanceOf[msg.sender] = SafeMath.safeSub(balanceOf[msg.sender], _value);
        totalSupply = SafeMath.safeSub(totalSupply,_value);
        emit Burn(msg.sender, _value);
        return true;
    }
 
    // Freeze tokens
    function freeze(uint256 _value) public returns (bool success) {
        assert(balanceOf[msg.sender] >= _value);
        assert(_value > 0);
        balanceOf[msg.sender] = SafeMath.safeSub(balanceOf[msg.sender], _value); 
        freezeOf[msg.sender] = SafeMath.safeAdd(freezeOf[msg.sender], _value); 
        emit Freeze(msg.sender, _value);
        return true;
    }
 
    // Unfreeze tokens
    function unfreeze(uint256 _value) public returns (bool success) {
        assert(freezeOf[msg.sender] >= _value);
        assert(_value > 0); 
        freezeOf[msg.sender] = SafeMath.safeSub(freezeOf[msg.sender], _value); 
        balanceOf[msg.sender] = SafeMath.safeAdd(balanceOf[msg.sender], _value);    
        emit Unfreeze(msg.sender, _value);
        return true;
    }
 
    // Withdraw Ether
    function withdrawEther(uint256 amount) public {
        assert(msg.sender == owner);
        owner.transfer(amount);
    }
}
