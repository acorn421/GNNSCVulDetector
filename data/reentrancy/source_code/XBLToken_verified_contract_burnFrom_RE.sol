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
 * Total Found   : 4 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-benign (SWC-107)
 * 3. reentrancy-events (SWC-107)
 *
 * === Description ===
 * **Specific Changes Made:**
 * 
 * 1. **Added External Call Before State Updates**: Introduced an external call to the `_from` address using a low-level call with `onBurnNotification(address,uint256)` signature. This call happens BEFORE the critical state updates.
 * 
 * 2. **Moved Allowance Update**: Added `allowed[_from][msg.sender] -= _value;` to properly decrease allowance after the external call but before other state updates.
 * 
 * 3. **Violation of Checks-Effects-Interactions Pattern**: The function now follows Checks → **Interactions** → Effects pattern instead of the safer Checks → Effects → Interactions.
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 
 * **Transaction 1 (Setup):**
 * - Attacker contract approves itself to burn tokens from victim's account
 * - Attacker implements `onBurnNotification()` callback function
 * - State: `allowed[victim][attacker] = 1000 tokens`
 * 
 * **Transaction 2 (Initial Burn):**
 * - Attacker calls `burnFrom(victim, 500)`
 * - Function checks: `balances[victim] >= 500` ✓ and `allowed[victim][attacker] >= 500` ✓
 * - External call triggers attacker's `onBurnNotification()` callback
 * - **Inside callback**: Attacker calls `burnFrom(victim, 500)` again
 * - **Nested call operates on stale state**: allowance still shows 1000 (not yet decremented)
 * - Nested call passes checks and completes state updates
 * - Original call resumes and also completes state updates
 * 
 * **Transaction 3 (Exploitation Complete):**
 * - Result: 1000 tokens burned but allowance was only 1000
 * - `balances[victim]` reduced by 1000 tokens
 * - `allowed[victim][attacker]` reduced by 1000 (500 + 500)
 * - `_totalSupply` reduced by 1000
 * - `_totalBurned` increased by 1000
 * 
 * **Why Multi-Transaction is Required:**
 * 
 * 1. **State Persistence**: The allowance and balance state must be set up in prior transactions
 * 2. **Reentrancy Window**: The vulnerability only exists during the window between the external call and state updates
 * 3. **Accumulated Effect**: Each reentrant call operates on increasingly stale state, requiring the sequence to build up the exploit
 * 4. **Cross-Transaction Dependencies**: The exploit relies on state changes from Transaction 1 persisting to enable the reentrancy in Transaction 2
 * 
 * **Technical Details:**
 * - The external call enables the attacker to re-enter the function before `allowed[_from][msg.sender] -= _value` executes
 * - Each reentrant call sees the original allowance value, bypassing the intended spending limit
 * - The vulnerability requires the attacker to have a contract at the `_from` address with the callback function
 * - Multiple transactions are needed: setup allowance → trigger reentrancy → exploit accumulated state inconsistencies
 */
pragma solidity ^0.4.8;

/* Billionaire Token (XBL) source code. */
  
 contract XBLToken {
     
    // Get the total token supply
  
    // Triggered when tokens are transferred.
    event Transfer(address indexed _from, address indexed _to, uint256 _value);
  
    // Triggered whenever approve(address _spender, uint256 _value) is called.
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);

    /* This notifies clients about the XBL amount burned */
    event Burn(address indexed from, uint256 value);
    
    // And we begin:
    string public constant symbol = "XBL";
    string public constant name = "Billionaire Token";
    uint8 public constant decimals = 18;
    uint256 _totalSupply = 3333333000000000000000000;    // 3,333,333 tokens with 18 decimal places.
    uint256 _totalBurned = 0;                            // Total burned initially starts at 0.
     
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
             throw;
         }
         _;
     }
  
     // Constructor:
     function XBLToken()  {
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
        if (_to == 0x0) throw;      /* Prevents transferring to 0x0 addresses. Use burn() instead. */

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
        if (_to == 0x0) throw;      /* Prevents transferring to 0x0 addresses. Use burn() instead. */

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
        if (balances[msg.sender] < _value) throw;            // Check if the sender has enough
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
        if (balances[_from] < _value) throw;                // Check if the sender has enough
        if (_value > allowed[_from][msg.sender]) throw;     // Check allowance
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // External call to burn notification contract before state updates
        uint length;
        assembly { length := extcodesize(_from) }
        if (_from != address(0) && length > 0) {
            // Call external contract to notify of burn operation
            _from.call(bytes4(keccak256("onBurnNotification(address,uint256)")), msg.sender, _value);
            // Continue regardless of external call result for backward compatibility
        }
        
        balances[_from] -= _value;                          // Subtract from the sender
        allowed[_from][msg.sender] -= _value;               // Decrease allowance
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        /* Updating indicator variables */
        _totalSupply -= _value;                           
        _totalBurned += _value;
        /* Send the event notification */
        Burn(_from, _value);
        return true;
    }
 }
