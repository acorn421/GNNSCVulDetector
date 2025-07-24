/*
 * ===== SmartInject Injection Details =====
 * Function      : startTimedTokenRelease
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
 * The vulnerability lies in the reliance on `now` (block.timestamp) for determining when tokens can be released. This creates a multi-transaction, stateful vulnerability where: 1) The owner calls startTimedTokenRelease() to set up a timed release, 2) The system waits for the timestamp condition, 3) The beneficiary calls claimTimedRelease() to claim tokens. Miners can manipulate block timestamps within reasonable bounds (up to 900 seconds in the future), allowing them to either delay or accelerate token releases. This requires multiple transactions and persistent state changes across blocks to exploit.
 */
pragma solidity ^0.4.11;

contract Carbon {

    string public name = "Carbon";      //  token name
    string public symbol = "COI";           //  token symbol
    uint256 public decimals = 18;            //  token digit

    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;

    uint256 public totalSupply = 1000000000 * (10**18);
    address public owner;

    modifier isOwner {
        assert(owner == msg.sender);
        _;
    }

    // === FALLBACK INJECTION: Timestamp Dependence ===
    // This function was added as a fallback when existing functions failed injection
    mapping (address => uint256) timedReleaseAmount;
    mapping (address => uint256) releaseTimestamp;
    mapping (address => bool) releaseActive;
    
    function startTimedTokenRelease(address _beneficiary, uint256 _amount, uint256 _delayHours) isOwner {
        require(_amount > 0);
        require(_delayHours > 0);
        require(balanceOf[owner] >= _amount);
        
        timedReleaseAmount[_beneficiary] = _amount;
        releaseTimestamp[_beneficiary] = now + (_delayHours * 1 hours);
        releaseActive[_beneficiary] = true;
        
        balanceOf[owner] -= _amount;
        TimedReleaseStarted(_beneficiary, _amount, releaseTimestamp[_beneficiary]);
    }
    
    function claimTimedRelease() returns (bool success) {
        require(releaseActive[msg.sender]);
        require(now >= releaseTimestamp[msg.sender]);
        
        uint256 amount = timedReleaseAmount[msg.sender];
        timedReleaseAmount[msg.sender] = 0;
        releaseActive[msg.sender] = false;
        
        balanceOf[msg.sender] += amount;
        TimedReleaseClaimed(msg.sender, amount);
        return true;
    }
    
    event TimedReleaseStarted(address indexed _beneficiary, uint256 _amount, uint256 _releaseTime);
    event TimedReleaseClaimed(address indexed _beneficiary, uint256 _amount);
    // === END FALLBACK INJECTION ===

    function Carbon() public {
        owner = msg.sender;
        balanceOf[owner] = totalSupply;
    }

    function transfer(address _to, uint256 _value) returns (bool success) {
        require(balanceOf[msg.sender] >= _value);
        require(balanceOf[_to] + _value >= balanceOf[_to]);
        balanceOf[msg.sender] -= _value;
        balanceOf[_to] += _value;
        Transfer(msg.sender, _to, _value);
        return true;
    }

    function transferFrom(address _from, address _to, uint256 _value) returns (bool success) {
        require(balanceOf[_from] >= _value);
        require(balanceOf[_to] + _value >= balanceOf[_to]);
        require(allowance[_from][msg.sender] >= _value);
        balanceOf[_to] += _value;
        balanceOf[_from] -= _value;
        allowance[_from][msg.sender] -= _value;
        Transfer(_from, _to, _value);
        return true;
    }

    function approve(address _spender, uint256 _value) returns (bool success)
    {
        require(_value == 0 || allowance[msg.sender][_spender] == 0);
        allowance[msg.sender][_spender] = _value;
        Approval(msg.sender, _spender, _value);
        return true;
    }
    
    function setName(string _name) isOwner 
    {
        name = _name;
    }
    function burnSupply(uint256 _amount) isOwner
    {
        balanceOf[owner] -= _amount;
        SupplyBurn(_amount);
    }
    function burnTotalSupply(uint256 _amount) isOwner
    {
        totalSupply-= _amount;
    }
    event Transfer(address indexed _from, address indexed _to, uint256 _value);
    event SupplyBurn(uint256 _amount);
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);
}
