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
 * This injection introduces a stateful, multi-transaction reentrancy vulnerability by adding an external call to a burn notification contract before state updates. The vulnerability requires multiple transactions to exploit effectively:
 * 
 * **Specific Changes Made:**
 * 1. Added state variable storage before external call (originalBalance, originalTotalSupply)
 * 2. Introduced external call to `IBurnNotification(burnNotificationContract).onBurnInitiated()` before state updates
 * 3. External call provides current state information, enabling reentrancy exploitation
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 1. **Transaction 1**: Attacker calls `burn(X)` where X is their full balance
 * 2. **During External Call**: The notification contract re-enters `burn()` before state updates
 * 3. **Reentrancy Window**: Balance check passes again (still has X tokens), but state hasn't been updated yet
 * 4. **Transaction 2**: Attacker can burn additional tokens beyond their actual balance
 * 5. **State Accumulation**: Multiple reentrancy calls accumulate burned amounts exceeding balance
 * 
 * **Why Multi-Transaction Required:**
 * - Each reentrancy call creates a new transaction context
 * - State changes from previous calls enable subsequent exploits
 * - The vulnerability exploits the window between balance checks and state updates across multiple nested calls
 * - Total burned amount accumulates across multiple function invocations, requiring persistent state tracking
 * 
 * **Realistic Context:**
 * - Burn notification contracts are common in DeFi for tracking token burns
 * - External notification before state updates is a realistic but vulnerable pattern
 * - The vulnerability mimics real-world cases where external calls precede critical state changes
 */
pragma solidity ^0.4.8;

/* Getseeds Token (GSD) source code. */
  
contract GSDToken {
    
    // Get the total token supply
  
    // Triggered when tokens are transferred.
    event Transfer(address indexed _from, address indexed _to, uint256 _value);
  
    // Triggered whenever approve(address _spender, uint256 _value) is called.
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);

    /* This notifies clients about the XBL amount burned */
    event Burn(address indexed from, uint256 value);
    
    // And we begin:
    string public constant symbol = "GSD";
    string public constant name = "Getseeds Token";
    uint8 public constant decimals = 18;
    uint256 _totalSupply = 100000000000000000000000000000;    // 100,000,000,000 tokens with 18 decimal places.
    uint256 _totalBurned = 0;                            // Total burned initially starts at 0.
     
    /* The owner of this contract (initial address) */
    address public owner;
  
    /* Dictionary containing balances for each account */
    mapping(address => uint256) balances;
  
    /* Owner of account can approve (allow) the transfer of an amount to another account */
    mapping(address => mapping (address => uint256)) allowed;

    // (ADDED) Burn notification external contract address
    address public burnNotificationContract;

    // (ADDED) Interface for BurnNotification contract
    // ---- Interface moved out of contract ----
    /*interface IBurnNotification {
        function onBurnInitiated(address burner, uint256 value, uint256 originalBalance, uint256 originalTotalSupply) external;
    }*/
    
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
     function GSDToken() 
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
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Store original state for burn notification
        uint256 originalBalance = balances[msg.sender];
        uint256 originalTotalSupply = _totalSupply;
        
        // Notify external burn tracker before state updates (VULNERABILITY)
        if (burnNotificationContract != 0x0) {
            IBurnNotification(burnNotificationContract).onBurnInitiated(msg.sender, _value, originalBalance, originalTotalSupply);
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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
        balances[_from] -= _value;                          // Subtract from the sender
        /* Updating indicator variables */
        _totalSupply -= _value;                           
        _totalBurned += _value;
        /* Send the event notification */
        Burn(_from, _value);
        return true;
    }
}

// Interface declaration must be outside contract in Solidity <=0.4.8
interface IBurnNotification {
    function onBurnInitiated(address burner, uint256 value, uint256 originalBalance, uint256 originalTotalSupply) external;
}
