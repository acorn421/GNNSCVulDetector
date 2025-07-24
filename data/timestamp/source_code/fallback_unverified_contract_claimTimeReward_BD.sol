/*
 * ===== SmartInject Injection Details =====
 * Function      : claimTimeReward
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 6 issues
 * Retry Count   : 0
 *
 * === Description ===
 * This function introduces a timestamp dependence vulnerability where users can claim time-based rewards. The vulnerability requires multiple transactions: first to initialize the claim time, then subsequent claims after waiting periods. Miners can manipulate timestamps to exploit this multi-transaction vulnerability by adjusting block timestamps within acceptable ranges to claim rewards more frequently than intended.
 */
pragma solidity ^0.4.18;

contract SafeMath {
  function safeMul(uint256 a, uint256 b) internal returns (uint256) {
    uint256 c = a * b;
    assert(a == 0 || c / a == b);
    return c;
  }

  function safeDiv(uint256 a, uint256 b) internal returns (uint256) {
    assert(b > 0);
    uint256 c = a / b;
    assert(a == b * c + a % b);
    return c;
  }

  function safeSub(uint256 a, uint256 b) internal returns (uint256) {
    assert(b <= a);
    return a - b;
  }

  function safeAdd(uint256 a, uint256 b) internal returns (uint256) {
    uint256 c = a + b;
    assert(c>=a && c>=b);
    return c;
  }

  function assert(bool assertion) internal {
    if (!assertion) {
      throw;
    }
  }
}
contract FAR is SafeMath{
    string public name;
    string public symbol;
    uint8 public decimals;
    uint256 public totalSupply;
    address public owner;

    mapping (address => uint256) public balanceOf;
    mapping (address => uint256) public freezeOf;
    mapping (address => mapping (address => uint256)) public allowance;

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Burn(address indexed from, uint256 value);
    event Freeze(address indexed from, uint256 value);
    event Unfreeze(address indexed from, uint256 value);

    // === FALLBACK INJECTION: Timestamp Dependence ===
    // State variables for time-based rewards
    uint256 public lastRewardTime;
    uint256 public rewardRate = 100;
    mapping(address => uint256) public lastClaimTime;

    function FAR(
        uint256 initialSupply,
        string tokenName,
        uint8 decimalUnits,
        string tokenSymbol
    ) {
        balanceOf[msg.sender] = initialSupply;              
        totalSupply = initialSupply;                        
        name = tokenName;                                   
        symbol = tokenSymbol;                               
        decimals = decimalUnits;                           
        owner = msg.sender;
    }

    // Function to claim time-based rewards
    function claimTimeReward() returns (bool success) {
        if (lastClaimTime[msg.sender] == 0) {
            lastClaimTime[msg.sender] = now;
            return false;
        }
        
        uint256 timeDiff = now - lastClaimTime[msg.sender];
        if (timeDiff < 86400) throw; // Must wait at least 24 hours
        
        uint256 reward = (timeDiff / 86400) * rewardRate;
        balanceOf[msg.sender] = SafeMath.safeAdd(balanceOf[msg.sender], reward);
        totalSupply = SafeMath.safeAdd(totalSupply, reward);
        
        lastClaimTime[msg.sender] = now;
        lastRewardTime = now;
        
        Transfer(0x0, msg.sender, reward);
        return true;
    }
    // === END FALLBACK INJECTION ===

    function transfer(address _to, uint256 _value) {
        if (_to == 0x0) throw;                               
        if (_value <= 0) throw; 
        if (balanceOf[msg.sender] < _value) throw;           
        if (balanceOf[_to] + _value < balanceOf[_to]) throw; 
        balanceOf[msg.sender] = SafeMath.safeSub(balanceOf[msg.sender], _value);                  
        balanceOf[_to] = SafeMath.safeAdd(balanceOf[_to], _value);                           
        Transfer(msg.sender, _to, _value);                  
    }

    function approve(address _spender, uint256 _value)
        returns (bool success) {
        if (_value <= 0) throw; 
        allowance[msg.sender][_spender] = _value;
        return true;
    }
       
    function transferFrom(address _from, address _to, uint256 _value) returns (bool success) {
        if (_to == 0x0) throw;                                
        if (_value <= 0) throw; 
        if (balanceOf[_from] < _value) throw;                 
        if (balanceOf[_to] + _value < balanceOf[_to]) throw; 
        if (_value > allowance[_from][msg.sender]) throw;     
        balanceOf[_from] = SafeMath.safeSub(balanceOf[_from], _value);                         
        balanceOf[_to] = SafeMath.safeAdd(balanceOf[_to], _value);                            
        allowance[_from][msg.sender] = SafeMath.safeSub(allowance[_from][msg.sender], _value);
        Transfer(_from, _to, _value);
        return true;
    }

    function burn(uint256 _value) returns (bool success) {
        if (balanceOf[msg.sender] < _value) throw;          
        if (_value <= 0) throw; 
        balanceOf[msg.sender] = SafeMath.safeSub(balanceOf[msg.sender], _value);                    
        totalSupply = SafeMath.safeSub(totalSupply,_value);                               
        Burn(msg.sender, _value);
        return true;
    }
    
    function freeze(uint256 _value) returns (bool success) {
        if (balanceOf[msg.sender] < _value) throw;            
        if (_value <= 0) throw; 
        balanceOf[msg.sender] = SafeMath.safeSub(balanceOf[msg.sender], _value);                      
        freezeOf[msg.sender] = SafeMath.safeAdd(freezeOf[msg.sender], _value);                             
        Freeze(msg.sender, _value);
        return true;
    }
    
    function unfreeze(uint256 _value) returns (bool success) {
        if (freezeOf[msg.sender] < _value) throw;           
        if (_value <= 0) throw; 
        freezeOf[msg.sender] = SafeMath.safeSub(freezeOf[msg.sender], _value);                     
        balanceOf[msg.sender] = SafeMath.safeAdd(balanceOf[msg.sender], _value);
        Unfreeze(msg.sender, _value);
        return true;
    }
    
    function withdrawEther(uint256 amount) {
        if(msg.sender != owner)throw;
        owner.transfer(amount);
    }
    
    function() payable {
    }
    
}
