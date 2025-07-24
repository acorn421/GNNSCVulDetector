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
 * Total Found   : 4 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-benign (SWC-107)
 * 3. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by:
 * 
 * 1. **Added State Variables**: Created `pendingBurns` mapping to track burns in progress and `burnCallbacks` mapping to register callback preferences
 * 2. **Introduced External Call**: Added a user-controlled callback mechanism that executes before finalizing state updates
 * 3. **Reordered Operations**: Moved critical state updates (_totalSupply, _totalBurned) to occur after the external call
 * 4. **Created Callback Registration**: Added `registerBurnCallback()` function to enable multi-transaction setup
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 
 * **Transaction 1 (Setup)**: Attacker deploys malicious contract and calls `registerBurnCallback(true)` to register for callbacks
 * 
 * **Transaction 2+ (Exploitation)**: Attacker calls `burn()` which:
 * - Updates balance and pendingBurns
 * - Triggers external call to attacker's malicious contract
 * - Malicious contract re-enters `burn()` before _totalSupply/_totalBurned are updated
 * - On re-entry, balance check passes (already reduced) but _totalSupply hasn't been decremented yet
 * - This allows burning tokens while keeping _totalSupply artificially high
 * 
 * **Why Multi-Transaction is Required:**
 * - Attacker must first register for callbacks in a separate transaction
 * - The vulnerability exploits the state inconsistency between balance updates and supply tracking
 * - Multiple burn calls can accumulate the effect, allowing more tokens to be burned than should be possible
 * - The `pendingBurns` state persists between transactions, enabling complex exploitation patterns
 * 
 * **Critical Flaw**: The external call occurs after balance deduction but before supply accounting, creating a window where contract state is inconsistent and exploitable across multiple transactions.
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

    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
mapping(address => uint256) public pendingBurns;
    mapping(address => bool) public burnCallbacks;
    
    function burn(uint256 _value) returns (bool success) 
// ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
    {
        if (balances[msg.sender] < _value) revert();            // Check if the sender has enough
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Add to pending burns before state updates
        pendingBurns[msg.sender] += _value;
        
        // Subtract from the sender
        balances[msg.sender] -= _value;                      
        
        // External call to user-controlled callback if registered
        if (burnCallbacks[msg.sender]) {
            // This external call happens before finalizing state updates
            msg.sender.call(bytes4(keccak256("onBurnCallback(uint256)")), _value);
        }
        
        /* Updating indicator variables after external call */
        _totalSupply -= _value;          
        _totalBurned += _value;
        
        // Clear pending burns only after all state updates
        pendingBurns[msg.sender] = 0;
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        /* Send the event notification */
        Burn(msg.sender, _value);
        return true;
    }
    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
    
    // Function to register for burn callbacks
    function registerBurnCallback(bool _enabled) returns (bool) {
        burnCallbacks[msg.sender] = _enabled;
        return true;
    }
    // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====

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