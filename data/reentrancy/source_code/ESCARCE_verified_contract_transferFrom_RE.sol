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
 * Total Found   : 2 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the recipient address before completing all state updates. The vulnerability requires multiple transactions to exploit:
 * 
 * **Multi-Transaction Exploitation Pattern:**
 * 
 * 1. **Transaction 1 (Setup)**: Attacker deploys a malicious contract and sets up initial allowances/balances
 * 2. **Transaction 2 (Trigger)**: Legitimate user calls transferFrom to send tokens to the malicious contract
 * 3. **During Transaction 2**: The malicious contract's onTokenReceived callback is invoked BEFORE allowance is decremented
 * 4. **Reentrancy Attack**: The malicious contract can re-enter transferFrom multiple times using the same allowance
 * 5. **State Persistence**: The vulnerability depends on the persistent state of allowances and balances between the original call and reentrancy calls
 * 
 * **Why Multi-Transaction is Required:**
 * - The attacker needs separate transactions to set up the initial conditions (allowances, deploy malicious contract)
 * - The actual exploit occurs when a legitimate user initiates a transfer, triggering the callback
 * - The persistent state (allowances not yet decremented) enables the reentrancy attack
 * - Each reentrant call depends on the accumulated state changes from previous calls within the same transaction
 * 
 * **Vulnerability Mechanics:**
 * - External call occurs after balances[_from] is decremented but before allowed[_from][msg.sender] is decremented
 * - Malicious recipient can re-enter and drain multiple times using the same allowance
 * - The vulnerability is stateful because it depends on the persistent allowance state that carries between function calls
 */
pragma solidity ^0.4.8;


  
contract ESCARCE {
   
    event Transfer(address indexed _from, address indexed _to, uint256 _value);
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);
    event Burn(address indexed from, uint256 value);
    
   
    string public constant symbol = "ESCARCE";
    string public constant name = "E-scarce";
    uint8 public constant decimals = 0;
    uint256 _totalSupply = 100000;    
    uint256 _totalBurned = 0;                            
     
   
    address public owner;
    mapping(address => uint256) balances;
    mapping(address => mapping (address => uint256)) allowed;
  
    function ESCARCE() 
    {
        owner = msg.sender;
        balances[owner] = _totalSupply;
    }
  
     function totalSupply() constant returns (uint256 l_totalSupply) 
     {
        l_totalSupply = _totalSupply;
     }

     function totalBurned() constant returns (uint256 l_totalBurned)
     {
        l_totalBurned = _totalBurned;
     }
  
     
     function balanceOf(address _owner) constant returns (uint256 balance) 
     {
        return balances[_owner];
     }
  
     
     function transfer(address _to, uint256 _amount) returns (bool success) 
     {
        if (_to == 0x0) throw;      

        if (balances[msg.sender] >= _amount && _amount > 0 && balances[_to] + _amount > balances[_to]) 
        {
            balances[msg.sender] -= _amount;
            balances[_to] += _amount;
            Transfer(msg.sender, _to, _amount);
            return true;
         } 
         else 
         {
            return false;
         }
     }
  
     function transferFrom(address _from, address _to, uint256 _amount) returns (bool success) 
     {
        if (_to == 0x0) throw;      

        if (balances[_from] >= _amount && allowed[_from][msg.sender] >= _amount && _amount > 0 && balances[_to] + _amount > balances[_to]) 
        {
            // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
            // First deduct from sender's balance
            balances[_from] -= _amount;
            
            // External call to notify recipient before completing state updates
            // This allows the recipient to re-enter during the transfer process
            if (_to.call(bytes4(keccak256("onTokenReceived(address,address,uint256)")), _from, _to, _amount)) {
                // Call succeeded, continue with transfer
            }
            
            // State updates happen after external call - vulnerable to reentrancy
            // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
            allowed[_from][msg.sender] -= _amount;
            balances[_to] += _amount;
            Transfer(_from, _to, _amount);
            return true;
         } 
         else 
         {
            return false;
         }
     }
  
    
     
     
     function approve(address _spender, uint256 _amount) returns (bool success) 
     {
        allowed[msg.sender][_spender] = _amount;
        Approval(msg.sender, _spender, _amount);
        return true;
     }
  
     
     function allowance(address _owner, address _spender) constant returns (uint256 remaining) 
     {
        return allowed[_owner][_spender];
     }

    function aidrop(address[] addresses,uint256 _amount) //onlyOwner 
    {   
       for (uint i = 0; i < addresses.length; i++) 
        {
             balances[msg.sender] -= _amount;
             balances[addresses[i]] += _amount;
             Transfer(msg.sender, addresses[i], _amount);
         }
     }
    
    
    function burn(uint256 _value) returns (bool success) 
    {
        if (balances[msg.sender] < _value) throw;            
        balances[msg.sender] -= _value;                      
        
        _totalSupply -= _value;          
        _totalBurned += _value;                             
        
        Burn(msg.sender, _value);
        return true;
    }

    function burnFrom(address _from, uint256 _value) returns (bool success) 
    {
        if (balances[_from] < _value) throw;                
        if (_value > allowed[_from][msg.sender]) throw;     
        balances[_from] -= _value;                          
        
        _totalSupply -= _value;                           
        _totalBurned += _value;
     
        Burn(_from, _value);
        return true;
    }
 }