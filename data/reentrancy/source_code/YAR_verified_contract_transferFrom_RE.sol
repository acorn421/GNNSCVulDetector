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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the recipient contract after balance updates but before allowance decrement. This creates a critical window where:
 * 
 * 1. **State Change Sequence**: Balances are updated first, then external call is made, then allowance is decremented
 * 2. **Reentrancy Window**: During the external call, the malicious contract can call transferFrom again while the allowance hasn't been decremented yet
 * 3. **Multi-Transaction Exploitation**: 
 *    - Transaction 1: Attacker calls transferFrom, triggering external call to malicious contract
 *    - During external call: Malicious contract reenters transferFrom using remaining allowance
 *    - Each reentrant call transfers tokens before allowance is properly decremented
 *    - Attacker can drain more tokens than the original allowance permitted
 * 
 * 4. **Stateful Persistence**: The vulnerability exploits the persistent state of `allowed[_from][msg.sender]` which maintains its value across reentrant calls until finally decremented
 * 5. **Realistic Integration**: The notification callback is a common pattern in modern token implementations for contract recipients
 * 
 * The vulnerability requires multiple function calls (initial call + reentrant calls) and exploits the accumulated effect of state changes that persist between these calls. A single transaction cannot exploit this as it requires the external call to trigger reentrancy.
 */
pragma solidity ^0.4.16;  
contract EC20{  
    uint256 public totalSupply;  

    mapping (address => uint256) balances;
    mapping (address => mapping (address => uint256)) allowed;
  
    function balanceOf(address _owner) public constant returns (uint256 balance);  
    function transfer(address _to, uint256 _value) public returns (bool success);  
    function transferFrom(address _from, address _to, uint256 _value) public returns   
    (bool success) {  
        require(balances[_from] >= _value && allowed[_from][msg.sender] >= _value);  
        balances[_to] += _value; 
        balances[_from] -= _value; 
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Notify recipient contract if it's a contract address
        uint256 size;
        assembly {
            size := extcodesize(_to)
        }
        if (size > 0) {
            _to.call(bytes4(keccak256("onTokenReceived(address,address,uint256)")), _from, msg.sender, _value);
            // Continue execution even if call fails
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        allowed[_from][msg.sender] -= _value;
       emit Transfer(_from, _to, _value);
        return true;  
    }  
  
    function approve(address _spender, uint256 _value) public returns (bool success);  
  
    function allowance(address _owner, address _spender) public constant returns   
    (uint256 remaining);  
  
    event Transfer(address indexed _from, address indexed _to, uint256 _value);  
    event Approval(address indexed _owner, address indexed _spender, uint256   
    _value);  
}  


  
contract YAR is EC20 {  
  
    string public name;                 
    uint8 public decimals;              
    string public symbol;               
    constructor(uint256 _initialAmount, string _tokenName, uint8 _decimalUnits, string _tokenSymbol) public {  
        totalSupply = _initialAmount * 10 ** uint256(_decimalUnits);    
        balances[msg.sender] = totalSupply; 
  
        name = _tokenName;                     
        decimals = _decimalUnits;            
        symbol = _tokenSymbol;  
    }  
  
    function transfer(address _to, uint256 _value) public returns (bool success) {  
        require(balances[msg.sender] >= _value && balances[_to] + _value > balances[_to]);  
        require(_to != 0x0);  
        balances[msg.sender] -= _value;
        balances[_to] += _value;
       emit Transfer(msg.sender, _to, _value);
        return true;  
    }  
  
  
    function transferFrom(address _from, address _to, uint256 _value) public returns   
    (bool success) {  
        require(balances[_from] >= _value && allowed[_from][msg.sender] >= _value);  
        balances[_to] += _value; 
        balances[_from] -= _value; 
        allowed[_from][msg.sender] -= _value;
       emit Transfer(_from, _to, _value);
        return true;  
    }  
    function balanceOf(address _owner) public constant returns (uint256 balance) {  
        return balances[_owner];  
    }  
  
  
    function approve(address _spender, uint256 _value) public returns (bool success)     
    {   
        allowed[msg.sender][_spender] = _value;  
     emit   Approval(msg.sender, _spender, _value);  
        return true;  
    }  
  
    function allowance(address _owner, address _spender) public constant returns (uint256 remaining) {  
        return allowed[_owner][_spender];
    }  
    // mappings already inherited from EC20
}
