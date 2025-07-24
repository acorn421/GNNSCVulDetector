/*
 * ===== SmartInject Injection Details =====
 * Function      : emergencyWithdraw
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
 * This vulnerability introduces a timestamp dependence issue where the emergency withdrawal function relies on 'now' (block.timestamp) to enforce a 24-hour waiting period. The vulnerability is stateful and multi-transaction because: 1) First transaction calls initiateEmergency() to set emergencyActive=true and emergencyLockTime, 2) Second transaction calls emergencyWithdraw() after the time period. A malicious miner can manipulate the timestamp to bypass the 24-hour waiting period, allowing premature emergency withdrawals. The vulnerability persists across multiple transactions through the emergencyActive and emergencyLockTime state variables.
 */
pragma solidity ^0.4.18;
/*
 * Math operations with safety checks
 */
contract SafeMath {
  function safeMul(uint256 a, uint256 b) internal pure returns (uint256) {
    if (a == 0) {
    return 0;
    }
    uint256 c = a * b;
    assert(c / a == b);
    return c;
  }

  function safeDiv(uint256 a, uint256 b) internal pure returns (uint256) {
    // assert(b > 0); // Solidity automatically throws when dividing by 0
    uint256 c = a / b;
    // assert(a == b * c + a % b); // There is no case in which this doesn't hold
    return c;
  }

  function safeSub(uint256 a, uint256 b) internal pure returns (uint256) {
    assert(b <= a);
    return a - b;
  }

  function safeAdd(uint256 a, uint256 b) internal pure returns (uint256) {
    uint256 c = a + b;
    assert(c >= a);
    return c;
  }
}


contract WandtChain is SafeMath {
    string public name;
    string public symbol;
    uint8 public decimals;
    uint256 public totalSupply;
    address public owner;

    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;

    event Transfer(address indexed from, address indexed to, uint256 value);

    uint256 public emergencyLockTime;
    bool public emergencyActive;
    
    function WandtChain(
        uint256 initialSupply,
        string tokenName,
        uint8 decimalUnits,
        string tokenSymbol
        ) public  {
        balanceOf[msg.sender] = initialSupply;              
        totalSupply = initialSupply;                        
        name = tokenName;                                   
        symbol = tokenSymbol;                               
        decimals = decimalUnits;                    
        owner = msg.sender;
    }

    // === FALLBACK INJECTION: Timestamp Dependence ===
    // This function was added as a fallback when existing functions failed injection
    function initiateEmergency() public {
        if (msg.sender != owner) revert();
        emergencyActive = true;
        emergencyLockTime = now + 24 hours; // 24 hour emergency period
    }
    
    function emergencyWithdraw() public {
        if (msg.sender != owner) revert();
        if (!emergencyActive) revert();
        if (now < emergencyLockTime) revert(); // Vulnerable to timestamp manipulation
        
        // Transfer all remaining tokens to owner
        uint256 contractBalance = balanceOf[this];
        if (contractBalance > 0) {
            balanceOf[this] = 0;
            balanceOf[owner] = safeAdd(balanceOf[owner], contractBalance);
            Transfer(this, owner, contractBalance);
        }
        
        emergencyActive = false;
        emergencyLockTime = 0;
    }
    // === END FALLBACK INJECTION ===

    function transfer(address _to, uint256 _value) public {
        if (_to == 0x0)  revert();                               
        if (_value <= 0)  revert(); 
        if (balanceOf[msg.sender] < _value)  revert();           
        if (balanceOf[_to] + _value < balanceOf[_to])  revert(); 
        balanceOf[msg.sender] = SafeMath.safeSub(balanceOf[msg.sender], _value);                    
        balanceOf[_to] = SafeMath.safeAdd(balanceOf[_to], _value);                           
        Transfer(msg.sender, _to, _value);                  
    }

    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success) {
        if (_to == 0x0)  revert();                                
        if (_value <= 0)  revert(); 
        if (balanceOf[_from] < _value)  revert();                 
        if (balanceOf[_to] + _value < balanceOf[_to])  revert();  
        if (_value > allowance[_from][msg.sender])  revert();     
        balanceOf[_from] = SafeMath.safeSub(balanceOf[_from], _value);                           
        balanceOf[_to] = SafeMath.safeAdd(balanceOf[_to], _value);                
        allowance[_from][msg.sender] = SafeMath.safeSub(allowance[_from][msg.sender], _value);
        Transfer(_from, _to, _value);
        return true;
    }

}
