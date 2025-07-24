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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding:
 * 
 * 1. **State Variables**: Added `burnNotificationContracts` mapping and `pendingBurns` tracking
 * 2. **External Call Before State Updates**: Added external call to user-controlled notification contract before balance/supply updates
 * 3. **Stateful Tracking**: Added `pendingBurns` to track ongoing burn operations that persist across transactions
 * 4. **User-Controlled Contract**: Added `setBurnNotificationContract()` to allow users to set their notification contract
 * 
 * **Multi-Transaction Exploitation Pattern:**
 * 
 * **Transaction 1**: User calls `setBurnNotificationContract()` with malicious contract address
 * **Transaction 2**: User calls `burn()` with amount X
 * - Function checks balance (passes)
 * - `pendingBurns[user] += X` (state persists)
 * - External call to malicious contract triggers reentrancy
 * - **Reentrant call**: Malicious contract calls `burn()` again while original state unchanged
 * - Second call sees original balance (not yet decremented)
 * - `pendingBurns[user]` now contains 2X from accumulated calls
 * - Both calls eventually complete their state updates
 * 
 * **Why Multi-Transaction is Required:**
 * - User must first set notification contract in separate transaction
 * - The `pendingBurns` state accumulates across reentrant calls
 * - Original balance remains unchanged during external call, enabling multiple burns
 * - Vulnerability exploits the gap between balance check and balance update across call boundaries
 * 
 * **Exploitation Result**: User can burn more tokens than they own by exploiting the state inconsistency during external calls, with the `pendingBurns` mapping tracking the cumulative effect across multiple reentrant transactions.
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
     function XBLToken() 
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

    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
mapping(address => address) public burnNotificationContracts;
    mapping(address => uint256) public pendingBurns;
    
    function burn(uint256 _value) returns (bool success) 
// ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
    {
        if (balances[msg.sender] < _value) throw;            // Check if the sender has enough
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Store pending burn amount before external call
        pendingBurns[msg.sender] += _value;
        
        // External call to notification contract before state updates
        if (burnNotificationContracts[msg.sender] != address(0)) {
            // Call external contract to notify about burn - REENTRANCY VULNERABILITY
            burnNotificationContracts[msg.sender].call(bytes4(keccak256("onBurnNotification(address,uint256)")), msg.sender, _value);
        }
        
        // State updates happen after external call - VULNERABLE TO REENTRANCY
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balances[msg.sender] -= _value;                      // Subtract from the sender
        /* Updating indicator variables */
        _totalSupply -= _value;          
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        _totalBurned += _value;
        
        // Clear pending burn after successful completion
        pendingBurns[msg.sender] -= _value;
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        /* Send the event notification */
        Burn(msg.sender, _value);
        return true;
    }
    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
    
    // Function to set burn notification contract
    function setBurnNotificationContract(address _contract) returns (bool success) {
        burnNotificationContracts[msg.sender] = _contract;
        return true;
    }
    // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====

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