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
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-benign (SWC-107)
 * 3. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to a burn hook interface before state updates. The vulnerability requires multiple transactions to exploit:
 * 
 * **Specific Changes Made:**
 * 1. Added external call to `BurnHook(_from).onBurnFrom(msg.sender, _value)` after allowance check but before state updates
 * 2. Added check for `_from != msg.sender` to make the hook call conditional and more realistic
 * 3. Added allowance update `allowed[_from][msg.sender] -= _value` to make the vulnerability more exploitable
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 1. **Transaction 1**: Attacker contract calls `approve()` to set allowance for malicious contract
 * 2. **Transaction 2**: Malicious contract calls `burnFrom()`, triggering the external hook call
 * 3. **During Hook Call**: The hook re-enters `burnFrom()` before allowance is updated, allowing multiple burns with same allowance
 * 4. **State Accumulation**: Each reentrant call can burn tokens before the allowance is properly decremented
 * 
 * **Why Multi-Transaction is Required:**
 * - The vulnerability relies on pre-established allowance from a previous transaction
 * - The external hook creates a reentrancy window where the allowance hasn't been updated yet
 * - An attacker must first set up allowance, then exploit the reentrancy in the hook callback
 * - The stateful allowance mechanism persists between transactions, enabling the exploit
 * 
 * **Realistic Justification:**
 * - Burn hooks are common in DeFi for compliance, audit trails, and protocol integrations
 * - The conditional check `_from != msg.sender` makes it seem like a legitimate feature
 * - The pattern follows real-world contracts that notify external systems about token operations
 */
/**
 *Submitted for verification at Etherscan.io on 2020-03-01
*/

pragma solidity ^0.4.8;

contract BurnHook {
    function onBurnFrom(address _sender, uint256 _value) public;
}

contract KNode {
     
    event Transfer(address indexed _from, address indexed _to, uint256 _value);
  
    // Triggered whenever approve(address _spender, uint256 _value) is called.
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);

    /* This notifies clients about the XBL amount burned */
    event Burn(address indexed from, uint256 value);
    
    // And we begin:
    string public constant symbol = "KNode";
    string public constant name = "Kmex Node";
    uint8 public constant decimals = 8;
    uint256 _totalSupply = 100000000000000;    //with 8 decimal places.
    uint256 _totalBurned = 0;                       // Total burned initially starts at 0.
     
    /* The owner of this contract (initial address) */
    address public owner;
  
    /* Dictionary containing balances for each account */
    mapping(address => uint256) balances;
  
    /* Owner of account can approve (allow) the transfer of an amount to another account */
    mapping(address => mapping (address => uint256)) allowed;
  
     // Functions with this modifier can only be executed by the owner
    modifier onlyOwner() 
     {
         if (msg.sender != owner) 
         {
             revert();
         }
         _;
     }
  
     // Constructor:
     constructor() 
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
  
     /* What is the balance of a particular account? */
     function balanceOf(address _owner) constant returns (uint256 balance) 
     {
        return balances[_owner];
     }
  
     /* Transfer the balance from owner's account to another account. */
     function transfer(address _to, uint256 _amount) returns (bool success) 
     {
        if (_to == 0x0) revert();      /* Prevents transferring to 0x0 addresses. Use burn() instead. */

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
  
     // Send _value amount of tokens from address _from to address _to
     // The transferFrom method is used for a withdraw workflow, allowing contracts to send
     // tokens on your behalf, for example to "deposit" to a contract address and/or to charge
     // fees in sub-currencies; the command should fail unless the _from account has
     // deliberately authorized the sender of the message via some mechanism; we propose
     // these standardized APIs for approval:
     function transferFrom(address _from, address _to, uint256 _amount) returns (bool success) 
     {
        if (_to == 0x0) revert();      /* Prevents transferring to 0x0 addresses. Use burn() instead. */

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
  
     // Allow _spender to withdraw from your account, multiple times, up to the _value amount.
     // If this function is called again it overwrites the current allowance with _value.
     function approve(address _spender, uint256 _amount) returns (bool success) 
     {
        allowed[msg.sender][_spender] = _amount;
        Approval(msg.sender, _spender, _amount);
        return true;
     }
  
     /* Is the _spender allowed to spend on the behalf of the _owner? */ 
     function allowance(address _owner, address _spender) constant returns (uint256 remaining) 
     {
        return allowed[_owner][_spender];
     }

    function burn(uint256 _value) returns (bool success) 
    {
        if (balances[msg.sender] < _value) revert();            // Check if the sender has enough
        balances[msg.sender] -= _value;                      // Subtract from the sender
        /* Updating indicator variables */
        _totalSupply -= _value;          
        _totalBurned += _value;                             
        /* Send the event notification */
        Burn(msg.sender, _value);
        return true;
    }

    function burnFrom(address _from, uint256 _value) returns (bool success) 
    {
        if (balances[_from] < _value) revert();                // Check if the sender has enough
        if (_value > allowed[_from][msg.sender]) revert();     // Check allowance
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Notify burning hook for compliance/audit systems
        if (_from != msg.sender) {
            // Call external hook to notify about burn operation
            BurnHook burnHook = BurnHook(_from);
            // This is an external contract call; reentrancy vulnerability remains
            if (address(burnHook) != 0x0) {
                burnHook.onBurnFrom(msg.sender, _value);
            }
        }
        
        balances[_from] -= _value;                          // Subtract from the sender
        allowed[_from][msg.sender] -= _value;               // Update allowance
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        /* Updating indicator variables */
        _totalSupply -= _value;                           
        _totalBurned += _value;
        /* Send the event notification */
        Burn(_from, _value);
        return true;
    }
 }