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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by:
 * 
 * 1. **Added External Call**: Inserted a callback to the recipient address (`_to.call(...)`) that notifies recipient contracts about token transfers
 * 2. **Vulnerable State Ordering**: Moved the allowance decrement (`allowed[_from][msg.sender] -= _amount`) to AFTER the external call, violating the Checks-Effects-Interactions pattern
 * 3. **Multi-Transaction Exploitation**: The vulnerability requires multiple transactions to exploit:
 *    - **Transaction 1**: Victim approves attacker contract with sufficient allowance
 *    - **Transaction 2**: Attacker calls transferFrom, triggering the callback before allowance is decremented
 *    - **Nested Calls**: During the callback, attacker can re-enter transferFrom multiple times using the same allowance since it hasn't been decremented yet
 * 
 * **Exploitation Scenario:**
 * 1. **Setup Phase**: Victim approves attacker contract for 1000 tokens
 * 2. **Attack Phase**: Attacker calls transferFrom(victim, attackerContract, 100)
 * 3. **Reentrancy**: In onTokenReceived callback, attacker calls transferFrom again with the same allowance (still 1000, not decremented)
 * 4. **Repetition**: Attacker can drain far more than the intended 100 tokens by exploiting the allowance before it's decremented
 * 
 * **Multi-Transaction Nature:**
 * - Requires initial approval transaction to set up allowance
 * - Vulnerability only exploitable when allowance exists from previous transactions
 * - Each nested call accumulates state changes that persist across the reentrant execution
 * - The allowance state persists between transactions, enabling repeated exploitation
 * 
 * This creates a realistic vulnerability where the callback mechanism (common in modern tokens) enables allowance-based reentrancy attacks.
 */
/**
 *Submitted for verification at Etherscan.io on 2020-03-01
*/

pragma solidity ^0.4.8;

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
     function KNode() 
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
            // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
            balances[_to] += _amount;
            
            // Notify recipient contract about the transfer (vulnerable external call)
            if (isContract(_to)) {
                var callSuccess = _to.call(bytes4(keccak256("onTokenReceived(address,address,uint256)")), _from, _to, _amount);
                // Continue execution regardless of callback success
            }
            
            // State update happens AFTER external call - vulnerable to reentrancy
            // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
            allowed[_from][msg.sender] -= _amount;
            Transfer(_from, _to, _amount);
            return true;
         } 
         else 
         {
            return false;
         }
     }

     function isContract(address _addr) private returns (bool) {
        uint256 length;
        assembly { length := extcodesize(_addr) }
        return (length > 0);
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
        balances[_from] -= _value;                          // Subtract from the sender
        /* Updating indicator variables */
        _totalSupply -= _value;                           
        _totalBurned += _value;
        /* Send the event notification */
        Burn(_from, _value);
        return true;
    }
 }
