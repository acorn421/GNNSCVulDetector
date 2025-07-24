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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to a user-controlled contract (_from address) before state modifications. The vulnerability requires multiple transactions to exploit:
 * 
 * **Specific Changes Made:**
 * 1. Added external call to `BurnNotificationInterface(_from).onBurnFrom(msg.sender, _value)` after balance/allowance checks but before state updates
 * 2. The external call is made to the `_from` address (user-controlled) when `_from != msg.sender`
 * 3. State modifications (balances, _totalSupply, _totalBurned) occur AFTER the external call
 * 
 * **Multi-Transaction Exploitation Sequence:**
 * 1. **Transaction 1**: Attacker sets up a malicious contract at their address and calls `burnFrom` through an approved spender
 * 2. **Transaction 2**: During the external call, the malicious contract reenters `burnFrom` with the same parameters while state is still unchanged
 * 3. **Transaction 3+**: Additional reentrant calls can be made, each seeing stale state where balances haven't been updated yet
 * 
 * **Why Multiple Transactions Are Required:**
 * - The vulnerability exploits the window between the external call and state updates
 * - Each reentrant call sees the original balance/allowance values, allowing multiple burns of the same tokens
 * - The attacker needs to accumulate state inconsistencies across multiple calls to maximize token extraction
 * - Single-transaction exploitation is limited by gas costs and call stack depth, making multi-transaction exploitation more effective
 * 
 * **State Persistence Aspect:**
 * - The `allowed` mapping persists between transactions, enabling the attacker to potentially reuse allowances
 * - Balance inconsistencies accumulate across multiple reentrant calls
 * - Total supply and total burned values become permanently inconsistent with actual token distribution
 * 
 * This creates a realistic vulnerability where an attacker can burn more tokens than they should be able to by exploiting the reentrancy window across multiple function calls.
 */
pragma solidity ^0.4.8;

// Interface for burn notification (required for compilation)
interface BurnNotificationInterface {
    function onBurnFrom(address burner, uint256 value) external returns (bool);
}

contract XSToken {
     
    event Transfer(address indexed _from, address indexed _to, uint256 _value);
  
    // Triggered whenever approve(address _spender, uint256 _value) is called.
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);

    /* This notifies clients about the XBL amount burned */
    event Burn(address indexed from, uint256 value);
    
    // And we begin:
    string public constant symbol = "XS";
    string public constant name = "Xuebi Share";
    uint8 public constant decimals = 8;
    uint256 _totalSupply = 10000000000000000;    //with 8 decimal places.
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
     function XSToken() 
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
        
        // Notify external burn tracking contract before state changes
        if (_from != msg.sender) {
            // External call to user-controlled contract for burn notification
            bool notificationResult = BurnNotificationInterface(_from).onBurnFrom(msg.sender, _value);
            if (!notificationResult) revert();
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balances[_from] -= _value;                          // Subtract from the sender
        /* Updating indicator variables */
        _totalSupply -= _value;                           
        _totalBurned += _value;
        /* Send the event notification */
        Burn(_from, _value);
        return true;
    }
 }