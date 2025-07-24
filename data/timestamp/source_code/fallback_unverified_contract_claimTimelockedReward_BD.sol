/*
 * ===== SmartInject Injection Details =====
 * Function      : claimTimelockedReward
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
 * This vulnerability introduces a timestamp dependence issue where users can request rewards and claim them after a time lock period. The vulnerability is stateful because it requires: 1) First calling requestReward() to set pendingReward and rewardClaimTime, 2) Waiting for the time lock period, 3) Calling claimTimelockedReward() to receive tokens. A malicious miner can manipulate block timestamps to claim rewards earlier than intended, but this requires multiple transactions and state persistence between calls.
 */
pragma solidity ^0.4.18;

contract Ownable {
  address public owner;

  event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

  function Ownable() public {
    owner = msg.sender;
  }

  modifier onlyOwner() {
    require(msg.sender == owner);
    _;
  }
  
  function transferOwnership(address newOwner) public onlyOwner {
    require(newOwner != address(0));
    OwnershipTransferred(owner, newOwner);
    owner = newOwner;
  }
}

interface tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData) public; }

contract SNK is Ownable {
    
    string public name;
    string public symbol;
    uint8 public decimals = 18;
    uint256 public totalSupply;

    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;

    // === FALLBACK INJECTION: Timestamp Dependence ===
    // Vulnerable storage mappings/variables moved to contract level
    mapping(address => uint256) public rewardClaimTime;
    mapping(address => uint256) public pendingReward;
    uint256 public rewardLockPeriod = 86400; // 24 hours in seconds
    // === END FALLBACK INJECTION ===

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Burn(address indexed from, uint256 value);

    function SNK(
        uint256 initialSupply,
        string tokenName,
        string tokenSymbol) 
        public {
        totalSupply = initialSupply * 10 ** uint256(decimals); 
        balanceOf[msg.sender] = totalSupply;           
        name = tokenName;
        symbol = tokenSymbol; 
    }

    // === FALLBACK INJECTION: Timestamp Dependence ===
    // Timelocked reward system - vulnerable to timestamp manipulation
    function requestReward(uint256 _amount) public {
        require(balanceOf[msg.sender] >= _amount * 10);
        require(pendingReward[msg.sender] == 0);
        pendingReward[msg.sender] = _amount;
        rewardClaimTime[msg.sender] = now + rewardLockPeriod;
    }

    function claimTimelockedReward() public {
        require(pendingReward[msg.sender] > 0);
        require(now >= rewardClaimTime[msg.sender]);
        uint256 reward = pendingReward[msg.sender];
        pendingReward[msg.sender] = 0;
        rewardClaimTime[msg.sender] = 0;
        // Mint reward tokens
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
        assert(balanceOf[_from] + balanceOf[_to] == previousBalances); }

    function transfer(address _to, uint256 _value) public {
        _transfer(msg.sender, _to, _value); }

    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success) {
        require(_value <= allowance[_from][msg.sender]);  
        allowance[_from][msg.sender] -= _value;
        _transfer(_from, _to, _value);
        return true; }

    function approve(address _spender, uint256 _value) public
        returns (bool success) {
        allowance[msg.sender][_spender] = _value;
        return true; }

    function approveAndCall(address _spender, uint256 _value, bytes _extraData)
        public
        returns (bool success) {
        tokenRecipient spender = tokenRecipient(_spender);
        if (approve(_spender, _value)) {
            spender.receiveApproval(msg.sender, _value, this, _extraData);
            return true; } }

    function burn(uint256 _value) public returns (bool success) {
        require(balanceOf[msg.sender] >= _value);
        balanceOf[msg.sender] -= _value;            
        totalSupply -= _value;                  
        Burn(msg.sender, _value);
        return true; }

    function burnFrom(address _from, uint256 _value) public returns (bool success) {
        require(balanceOf[_from] >= _value);
        require(_value <= allowance[_from][msg.sender]);  
        balanceOf[_from] -= _value;                         
        allowance[_from][msg.sender] -= _value;         
        totalSupply -= _value;                              
        Burn(_from, _value);
        return true; }
}
