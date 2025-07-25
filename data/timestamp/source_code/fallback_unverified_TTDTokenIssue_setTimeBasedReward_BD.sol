/*
 * ===== SmartInject Injection Details =====
 * Function      : setTimeBasedReward
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
 * This vulnerability introduces a timestamp dependence issue that requires multiple transactions to exploit. The vulnerability allows miners to manipulate block timestamps to maximize rewards over multiple claims. An attacker would need to: 1) First activate the reward system, 2) Make initial claims to establish state, 3) Then manipulate timestamps across multiple blocks/transactions to claim larger rewards than intended. The vulnerability is stateful because it relies on rewardLastClaimed mapping and rewardPool state that persists between transactions.
 */
pragma solidity ^0.4.18;

library SafeOpt {
    function mul(uint256 a, uint256 b) internal pure returns (uint256) {
        if (a == 0) {
            return 0;
        }
        uint256 c = a * b;
        assert(c / a == b);
        return c;
    }

    function div(uint256 a, uint256 b) internal pure returns (uint256) {
        assert(b > 0); 
        uint256 c = a / b;
        assert(a == b * c);
        return c;
    }

    function sub(uint256 a, uint256 b) internal pure returns (uint256) {
        uint256 c = a - b;
        assert(b <= a);
        assert(a == c + b);
        return c;
    }

    function add(uint256 a, uint256 b) internal pure returns (uint256) {
        uint256 c = a + b;
        assert(c >= a);
        assert(a == c - b);
        return c;
    }
}
contract TTDTokenIssue {
    uint256 public lastYearTotalSupply = 15 * 10 ** 26; 
    uint8   public affectedCount = 0;
    bool    public initialYear = true; 
    //uint16  public blockHeight = 2102400;
    address public tokenContractAddress;
    uint16  public preRate = 1000; 
    uint256 public lastBlockNumber;

    // === FALLBACK INJECTION: Timestamp Dependence ===
    // Moved the following state variable declarations outside the constructor
    mapping(address => uint256) public rewardLastClaimed;
    uint256 public rewardPool = 1000000 * 10 ** 18;
    uint256 public rewardStartTime;
    bool public rewardSystemActive = false;
    address public owner;
    mapping(address => uint256) public balanceOf; // Added to avoid undeclared mapping
    uint256 public totalSupply; // Added to avoid undeclared variable

    event Transfer(address indexed from, address indexed to, uint256 value);

    function TTDTokenIssue (address _tokenContractAddress) public {
        owner = msg.sender;
        tokenContractAddress = _tokenContractAddress;
        lastBlockNumber = block.number;
    }
    
    function activateRewardSystem() public {
        require(msg.sender == owner);
        require(!rewardSystemActive);
        rewardSystemActive = true;
        rewardStartTime = now;
    }
    
    function setTimeBasedReward() public {
        require(rewardSystemActive);
        require(now >= rewardStartTime + 1 days);
        require(balanceOf[msg.sender] > 0);
        
        uint256 timeSinceLastClaim = now - rewardLastClaimed[msg.sender];
        if(rewardLastClaimed[msg.sender] == 0) {
            timeSinceLastClaim = now - rewardStartTime;
        }
        
        require(timeSinceLastClaim >= 24 hours);
        
        // Vulnerable: Using timestamp for reward calculation
        uint256 rewardAmount = (balanceOf[msg.sender] * timeSinceLastClaim) / (1 days * 1000);
        
        if(rewardAmount > rewardPool) {
            rewardAmount = rewardPool;
        }
        
        require(rewardAmount > 0);
        require(rewardPool >= rewardAmount);
        
        rewardPool -= rewardAmount;
        balanceOf[msg.sender] = SafeOpt.add(balanceOf[msg.sender], rewardAmount);
        totalSupply = SafeOpt.add(totalSupply, rewardAmount);
        rewardLastClaimed[msg.sender] = now;
        
        Transfer(0x0, msg.sender, rewardAmount);
    }
    // === END FALLBACK INJECTION ===

    function returnRate() internal returns (uint256){
        if(affectedCount == 10){
            if(preRate > 100){
                preRate -= 100;
            }
            affectedCount = 0;
        }
        return SafeOpt.div(preRate, 10);
    }

    function issue() public  {
        if(initialYear){
            require(SafeOpt.sub(block.number, lastBlockNumber) > 2102400);
            initialYear = false;
        }
        require(SafeOpt.sub(block.number, lastBlockNumber) > 2102400);
        TTDToken tokenContract = TTDToken(tokenContractAddress);
        if(affectedCount == 10){
            lastYearTotalSupply = tokenContract.totalSupply();
        }
        uint256 amount = SafeOpt.div(SafeOpt.mul(lastYearTotalSupply, returnRate()), 10000);
        require(amount > 0);
        tokenContract.issue(amount);
        lastBlockNumber = block.number;
        affectedCount += 1;
    }
}


interface tokenRecipient {
    function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData) public;
}

contract TTDToken {
    string public name = 'TTD Token';
    string public symbol = 'TTD';
    uint8 public decimals = 18;
    uint256 public totalSupply = 100 * 10 ** 26;

    address public issueContractAddress;
    address public owner;

    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);
    event Burn(address indexed from, uint256 value);
    event Issue(uint256 amount);

    function TTDToken() public {
        owner = msg.sender;
        balanceOf[owner] = totalSupply;
        issueContractAddress = new TTDTokenIssue(address(this));
    }

    function issue(uint256 amount) public {
        require(msg.sender == issueContractAddress);
        balanceOf[owner] = SafeOpt.add(balanceOf[owner], amount);
        totalSupply = SafeOpt.add(totalSupply, amount);
        Issue(amount);
    }

    function balanceOf(address _owner) public view returns (uint256 balance) {
        return balanceOf[_owner];
    }

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

    function transfer(address _to, uint256 _value) public returns (bool success){
        _transfer(msg.sender, _to, _value);
        return true;
    }

    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success) {
        require(_value <= allowance[_from][msg.sender]);
        allowance[_from][msg.sender] -= _value;
        _transfer(_from, _to, _value);
        return true;
    }

    function approve(address _spender, uint256 _value) public returns (bool success) {
        require(_value <= balanceOf[msg.sender]);
        allowance[msg.sender][_spender] = _value;
        Approval(msg.sender, _spender, _value);
        return true;
    }

    function approveAndCall(address _spender, uint256 _value, bytes _extraData) public returns (bool success) {
        tokenRecipient spender = tokenRecipient(_spender);
        if (approve(_spender, _value)) {
            spender.receiveApproval(msg.sender, _value, this, _extraData);
            return true;
        }
    }

    function allowance(address _owner, address _spender) view public returns (uint256 remaining) {
        return allowance[_owner][_spender];
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
