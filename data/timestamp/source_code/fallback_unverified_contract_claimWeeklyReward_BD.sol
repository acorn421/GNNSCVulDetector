/*
 * ===== SmartInject Injection Details =====
 * Function      : claimWeeklyReward
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
 * This function introduces a timestamp dependence vulnerability where miners can manipulate block timestamps to claim rewards more frequently than intended. The vulnerability is stateful and multi-transaction because: 1) It requires users to first acquire tokens through createTokens(), 2) The state variables lastRewardTime and lastClaimTime persist between transactions, 3) Exploitation requires multiple calls with manipulated timestamps across different blocks, 4) The vulnerability accumulates over time as attackers can claim rewards more frequently than the intended weekly schedule.
 */
pragma solidity ^0.4.18;

/**
 * @title SafeMath
 * @dev Math operations with safety checks that throw on error
 */
library SafeMath {
    function add(uint256 a, uint256 b) internal pure returns (uint256) {
        uint256 c = a + b;
        assert(c >= a);
        return c;
    }  

    function div(uint256 a, uint256 b) internal pure returns (uint256) {
        // assert(b > 0); // Solidity automatically throws when dividing by 0
        uint256 c = a / b;
        // assert(a == b * c + a % b); // There is no case in which this doesn't hold
        return c;
    }
  
    function mul(uint256 a, uint256 b) internal pure returns (uint256) {
        uint256 c = a * b;
        assert(a == 0 || c / a == b);
        return c;
    }

    function sub(uint256 a, uint256 b) internal pure returns (uint256) {
        assert(b <= a);
        return a - b;
    }
}

contract BCE {
    
    using SafeMath for uint256;
    
    uint public _totalSupply = 0; 
    
    string public constant symbol = "BCE";
    string public constant name = "Bitcoin Ether";
    uint8 public constant decimals = 18;
	uint256 public totalSupply = _totalSupply * 10 ** uint256(decimals);
    
    // 1 ether = 500 bitcoin ethers
    uint256 public constant RATE = 500; 
    
    address public owner;
    
    event Transfer(address indexed _from, address indexed _to, uint256 _value);
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);
    
    mapping (address => uint256) balances;
    mapping (address => mapping (address => uint256)) allowed;

    // === FALLBACK INJECTION: Timestamp Dependence ===
    uint256 public lastRewardTime;
    uint256 public constant REWARD_AMOUNT = 1000 * 10**18; // 1000 BCE tokens
    mapping(address => uint256) public lastClaimTime;
    
    function claimWeeklyReward() public {
        require(balances[msg.sender] >= 100 * 10**18); // Must hold at least 100 BCE
        require(now >= lastClaimTime[msg.sender] + 7 days); // 7 days cooldown
        
        // Vulnerable: Uses block.timestamp for critical timing logic
        // Miners can manipulate timestamp within ~900 seconds
        if (now >= lastRewardTime + 1 weeks) {
            lastRewardTime = now;
            balances[msg.sender] = balances[msg.sender].add(REWARD_AMOUNT);
            _totalSupply = _totalSupply.add(REWARD_AMOUNT);
            lastClaimTime[msg.sender] = now;
        }
    }
    // === END FALLBACK INJECTION ===

	function () public payable {
        createTokens();
    }
    
    function BCEToken() public {
        owner = msg.sender;
    }
    
	function createTokens() public payable {
	    require(_totalSupply <= 21000000); // Max Bitcoin Ethers in circulation = 21 mil. 
        require(msg.value > 0);
        uint256 tokens = msg.value.mul(RATE);
        balances[msg.sender] = balances[msg.sender].add(tokens);
        _totalSupply = _totalSupply.add(tokens);
        owner.transfer(msg.value);
    } 
    
    function balanceOf(address _owner) public constant returns (uint256 balance){
        return balances[_owner];
    }
    
    function transfer(address _to, uint256 _value) internal returns (bool success) {
		require(_to != 0x0);
        require(balances[msg.sender] >= _value && _value > 0);
        balances[msg.sender] = balances[msg.sender].sub(_value);
        balances[_to] = balances[_to].add(_value);
        Transfer(msg.sender, _to, _value);
        return true;
    }
    
    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success){
		require(_to != 0x0);
        require(allowed [_from][msg.sender] >= 0 && balances[_from] >= _value && _value > 0);
        balances[_from] = balances[_from].sub(_value);
        balances[_to] = balances[_to].add(_value);
        allowed[_from][msg.sender] = allowed[_from][msg.sender].sub(_value);
        Transfer(_from, _to, _value);
        return true;
    }
    
    function approve(address _spender, uint256 _value) public returns (bool success){
        allowed[msg.sender][_spender] = _value;
        Approval(msg.sender, _spender, _value);
        return true;
    }
    
    function allowance(address _owner, address _spender) public constant returns (uint256 remaining){
        return allowed[_owner][_spender];
    }
}
