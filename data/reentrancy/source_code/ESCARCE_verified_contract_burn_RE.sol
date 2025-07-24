/*
 * ===== SmartInject Injection Details =====
 * Function      : burn
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
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-benign (SWC-107)
 * 3. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to a user-controlled `burnHandler` contract before state updates. This creates a classic reentrancy vulnerability where:
 * 
 * 1. **Multi-Transaction Setup**: An attacker must first deploy a malicious burn handler contract and somehow get it registered as the `burnHandler` (through another function or if there's a setter)
 * 
 * 2. **State Accumulation Exploitation**: The vulnerability requires multiple transactions to be profitable:
 *    - Transaction 1: Attacker calls burn() with some tokens
 *    - During execution, the external call to burnHandler allows reentrancy
 *    - The malicious handler can call burn() again before the original state updates complete
 *    - This allows burning the same tokens multiple times, artificially inflating _totalBurned
 * 
 * 3. **Persistent State Manipulation**: The vulnerability exploits the fact that balances and _totalBurned persist between transactions, allowing accumulated manipulation across multiple calls
 * 
 * 4. **Realistic Integration**: The burn notification pattern is common in DeFi protocols for integration with external systems, making this a realistic vulnerability
 * 
 * The vulnerability cannot be exploited in a single transaction because the attacker needs to:
 * - First establish the malicious handler
 * - Then trigger the burn sequence
 * - Potentially make multiple reentrant calls to maximize the exploit
 * - The state changes accumulate across these separate operations
 */
pragma solidity ^0.4.8;

// BurnHandler interface added to allow calls in the vulnerable burn()
interface BurnHandler {
    function onBurn(address from, uint256 value) external;
}

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
    address public burnHandler; // add burnHandler storage
    mapping(address => uint256) balances;
    mapping(address => mapping (address => uint256)) allowed;
  
    constructor() public // updated to constructor syntax
    {
        owner = msg.sender;
        balances[owner] = _totalSupply;
    }
  
     function totalSupply() public constant returns (uint256 l_totalSupply) 
     {
        l_totalSupply = _totalSupply;
     }

     function totalBurned() public constant returns (uint256 l_totalBurned)
     {
        l_totalBurned = _totalBurned;
     }
  
     
     function balanceOf(address _owner) public constant returns (uint256 balance) 
     {
        return balances[_owner];
     }
  
     
     function transfer(address _to, uint256 _amount) public returns (bool success) 
     {
        if (_to == address(0)) revert();      // replaced throw with revert and 0x0 with address(0)

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
  
     function transferFrom(address _from, address _to, uint256 _amount) public returns (bool success) 
     {
        if (_to == address(0)) revert();      // replaced throw with revert

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
  
    
     
     
     function approve(address _spender, uint256 _amount) public returns (bool success) 
     {
        allowed[msg.sender][_spender] = _amount;
        Approval(msg.sender, _spender, _amount);
        return true;
     }
  
     
     function allowance(address _owner, address _spender) public constant returns (uint256 remaining) 
     {
        return allowed[_owner][_spender];
     }

    function aidrop(address[] addresses,uint256 _amount) public //onlyOwner 
    {   
       for (uint i = 0; i < addresses.length; i++) 
        {
             balances[msg.sender] -= _amount;
             balances[addresses[i]] += _amount;
             Transfer(msg.sender, addresses[i], _amount);
         }
     }
    
    
    function burn(uint256 _value) public returns (bool success) 
    {
        if (balances[msg.sender] < _value) revert();   // replaced throw with revert            
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Notify external burn handler before state updates
        if (burnHandler != address(0)) {
            BurnHandler(burnHandler).onBurn(msg.sender, _value);
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balances[msg.sender] -= _value;                      
        _totalSupply -= _value;          
        _totalBurned += _value;                             
        
        Burn(msg.sender, _value);
        return true;
    }

    function burnFrom(address _from, uint256 _value) public returns (bool success) 
    {
        if (balances[_from] < _value) revert();                // replaced throw with revert
        if (_value > allowed[_from][msg.sender]) revert();     // replaced throw with revert
        balances[_from] -= _value;                          
        
        _totalSupply -= _value;                           
        _totalBurned += _value;
     
        Burn(_from, _value);
        return true;
    }
 }
