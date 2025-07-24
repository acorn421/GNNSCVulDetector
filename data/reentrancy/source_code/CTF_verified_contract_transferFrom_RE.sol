/*
 * ===== SmartInject Injection Details =====
 * Function      : transferFrom
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 2 findings
 * Total Found   : 3 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the recipient contract after balance updates but before allowance updates. The vulnerability creates a window where state is inconsistent across multiple transactions: balances are updated but allowances are not yet decremented. This enables multi-transaction exploitation where:
 * 
 * 1. Transaction 1: Initial transferFrom call updates balances and triggers external call to recipient
 * 2. Transaction 2: During the callback, the recipient can call transferFrom again with the same allowance (since it hasn't been decremented yet) but with updated balances
 * 3. Transaction 3+: Additional exploitation rounds can occur before the original allowance update completes
 * 
 * The vulnerability is stateful because it depends on the persistent state changes (balance updates) from the first transaction, and multi-transaction because the exploit requires the callback to make subsequent calls to transferFrom while the original call is still in progress. The external call creates a reentrancy window where the contract state is inconsistent between transactions.
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
    assert(c >= a && c >= b);
    return c;
  }

  function assert(bool assertion) internal {
    if (!assertion) {
      throw;
    }
  }
}

contract CTF is SafeMath{
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
    
    function CTF(
        uint256 initialSupply,
        string tokenName,
        uint8 decimalUnits,
        string tokenSymbol
        ) public {
        balanceOf[msg.sender] = initialSupply;              
        totalSupply = initialSupply;                        
        name = tokenName;                                   
        symbol = tokenSymbol;                               
        decimals = decimalUnits;                            
        owner = msg.sender;
    }
    
    function transfer(address _to, uint256 _value) public {
        if (_to == 0x0) throw;                               
        if (_value <= 0) throw; 
        if (balanceOf[msg.sender] < _value) throw;           
        if (balanceOf[_to] + _value < balanceOf[_to]) throw; 
        balanceOf[msg.sender] = SafeMath.safeSub(balanceOf[msg.sender], _value);                     
        balanceOf[_to] = SafeMath.safeAdd(balanceOf[_to], _value);                            
        emit Transfer(msg.sender, _to, _value);                   
    }
    
    function approve(address _spender, uint256 _value) public
        returns (bool success) {
        if (_value <= 0) throw; 
        allowance[msg.sender][_spender] = _value;
        return true;
    }
       
    
    function transferFrom(address _from, address _to, uint256 _value) public returns (bool) {
        if (_to == 0x0) throw;                                
        if (_value <= 0) throw; 
        if (balanceOf[_from] < _value) throw;                 
        if (balanceOf[_to] + _value < balanceOf[_to]) throw;  
        if (_value > allowance[_from][msg.sender]) throw;     
        balanceOf[_from] = SafeMath.safeSub(balanceOf[_from], _value);                           
        balanceOf[_to] = SafeMath.safeAdd(balanceOf[_to], _value);                             
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // Vulnerable: External call to recipient before allowance update
        if (isContract(_to)) {
            address(_to).call(abi.encodeWithSignature("onTokenReceived(address,address,uint256)", _from, _to, _value));
            // Continue regardless of callback result
        }
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        allowance[_from][msg.sender] = SafeMath.safeSub(allowance[_from][msg.sender], _value);
        emit Transfer(_from, _to, _value);
        return true;
    }

    function isContract(address _addr) internal view returns (bool) {
        uint256 size;
        assembly { size := extcodesize(_addr) }
        return size > 0;
    }

    function burn(uint256 _value) public returns (bool) {
        if (balanceOf[msg.sender] < _value) throw;            
        if (_value <= 0) throw; 
        balanceOf[msg.sender] = SafeMath.safeSub(balanceOf[msg.sender], _value);                      
        totalSupply = SafeMath.safeSub(totalSupply,_value);                                
        emit Burn(msg.sender, _value);
        return true;
    }
    
    function freeze(uint256 _value) public returns (bool) {
        if (balanceOf[msg.sender] < _value) throw;            
        if (_value <= 0) throw; 
        balanceOf[msg.sender] = SafeMath.safeSub(balanceOf[msg.sender], _value);                      
        freezeOf[msg.sender] = SafeMath.safeAdd(freezeOf[msg.sender], _value);                                
        emit Freeze(msg.sender, _value);
        return true;
    }
    
    function unfreeze(uint256 _value) public returns (bool) {
        if (freezeOf[msg.sender] < _value) throw;            
        if (_value <= 0) throw; 
        freezeOf[msg.sender] = SafeMath.safeSub(freezeOf[msg.sender], _value);                      
        balanceOf[msg.sender] = SafeMath.safeAdd(balanceOf[msg.sender], _value);
        emit Unfreeze(msg.sender, _value);
        return true;
    }
        
    function withdrawEther(uint256 amount) public {
        if(msg.sender != owner)throw;
        owner.transfer(amount);
    }
                
    function() public payable {
    }    
}
