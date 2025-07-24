/*
 * ===== SmartInject Injection Details =====
 * Function      : burnFrom
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 3 findings
 * Total Found   : 3 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-eth (SWC-107)
 * 2. reentrancy-benign (SWC-107)
 * 3. reentrancy-events (SWC-107)
 *
 * === Description ===
 * **STATEFUL MULTI-TRANSACTION REENTRANCY VULNERABILITY INJECTED**
 * 
 * **Specific Changes Made:**
 * 1. **Added External Call Before State Updates**: Inserted `_from.call.value(0)(bytes4(keccak256("onTokenBurn(uint256)")), _value)` callback after input validation but before critical state modifications
 * 2. **Moved State Updates After External Call**: The `balances[_from] -= _value` and other state changes now occur AFTER the external call, violating the Checks-Effects-Interactions pattern
 * 3. **Added Missing Allowance Update**: Added `allowed[_from][msg.sender] -= _value` to make the vulnerability more realistic and exploitable
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 
 * **Transaction 1 - Setup Phase:**
 * - Attacker deploys malicious contract at address `AttackerContract`
 * - Victim approves `AttackerContract` to burn tokens via `approve(AttackerContract, 1000)`
 * - Attacker calls `burnFrom(AttackerContract, 100)` - this triggers the callback to `AttackerContract.onTokenBurn(100)`
 * 
 * **Transaction 2 - Reentrancy Attack:**
 * - During the callback in Transaction 1, the malicious contract's `onTokenBurn` function calls `burnFrom(AttackerContract, 100)` again
 * - At this point, the first call hasn't updated the balances yet, so the second call sees the original balance
 * - The second call succeeds and calls back again, creating a reentrancy loop
 * 
 * **Why This Requires Multiple Transactions:**
 * 1. **State Accumulation**: The vulnerability exploits the fact that allowances and balances persist between transactions
 * 2. **Callback Dependency**: The attack requires the victim to have a contract that implements the callback, which must be deployed in a separate transaction
 * 3. **Approval Setup**: The allowance must be set up in advance through the `approve` function
 * 4. **Persistent State Exploitation**: Each reentrant call exploits the fact that state updates (balance reduction) happen after the external call, allowing multiple burns with the same initial balance
 * 
 * **Exploitation Steps:**
 * 1. Deploy malicious contract with `onTokenBurn` function that re-enters `burnFrom`
 * 2. Get approval from victim to burn tokens
 * 3. Call `burnFrom` - this triggers callback before state updates
 * 4. In callback, call `burnFrom` again with same parameters
 * 5. Repeat until all allowance is consumed or balance is drained
 * 
 * **Why Single Transaction Exploitation is Impossible:**
 * - The callback mechanism requires a deployed contract with the callback function
 * - The allowance must be pre-established through `approve`
 * - The reentrancy depends on state that exists across transaction boundaries
 * - The attack leverages the persistent nature of the allowance system across multiple function calls
 * 
 * This creates a realistic, stateful vulnerability that requires multiple transactions to set up and exploit, making it much more subtle and dangerous than simple single-transaction reentrancy attacks.
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
            balances[_from] -= _amount;
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
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Add callback to _from address before state updates - VULNERABILITY INTRODUCED
        if (_from.call.value(0)(bytes4(keccak256("onTokenBurn(uint256)")), _value)) {
            // Callback succeeded, continue with burn
        }
        
        balances[_from] -= _value;                          
        allowed[_from][msg.sender] -= _value;  // Add allowance update that was missing
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        
        _totalSupply -= _value;                           
        _totalBurned += _value;
     
        Burn(_from, _value);
        return true;
    }
 }