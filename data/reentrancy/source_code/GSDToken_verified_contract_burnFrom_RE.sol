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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by:
 * 
 * 1. **Added External Call Before State Updates**: Inserted a call to `_from.call(bytes4(keccak256("onTokenBurn(address,uint256)")), msg.sender, _value)` before updating the critical state variables. This creates a reentrancy window where the external contract can call back into `burnFrom`.
 * 
 * 2. **State Persistence Between Transactions**: The vulnerability exploits the fact that allowances and balances are persistent state that can be manipulated across multiple transactions. An attacker can:
 *    - Transaction 1: Set up a malicious contract as the token holder (`_from`)
 *    - Transaction 2: Another party calls `burnFrom` on the malicious contract
 *    - During the external call, the malicious contract can re-enter `burnFrom` with the same parameters since state hasn't been updated yet
 * 
 * 3. **Multi-Transaction Exploitation Path**:
 *    - **Setup Phase** (Transaction 1): Deploy malicious contract that implements `onTokenBurn` callback
 *    - **Approval Phase** (Transaction 2): Token holder approves the malicious contract to spend tokens
 *    - **Exploitation Phase** (Transaction 3): Attacker calls `burnFrom` on the malicious contract
 *    - **Reentrancy Phase** (During Transaction 3): The malicious contract's `onTokenBurn` callback re-enters `burnFrom` before state is updated, allowing double-spending of allowances
 * 
 * 4. **Why Multi-Transaction is Required**:
 *    - The attacker needs to first establish the malicious contract as a token holder
 *    - The approval mechanism requires separate transactions to set up allowances
 *    - The exploit depends on the accumulated state from previous transactions (token balance, allowances)
 *    - A single transaction cannot both set up the attack scenario AND exploit the reentrancy
 * 
 * This creates a realistic vulnerability where the external call to notify the token holder creates a reentrancy vector that can be exploited across multiple transactions by manipulating the persistent state of allowances and balances.
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
        
        // Notify the token holder about the burn before updating state
        if (_from != msg.sender) {
            // Call notification function on _from address if it's a contract
            if (_from.call(bytes4(keccak256("onTokenBurn(address,uint256)")), msg.sender, _value)) {
                // Notification successful
            }
        }
        
        balances[_from] -= _value;                          // Subtract from the sender
        allowed[_from][msg.sender] -= _value;               // Reduce allowance
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        /* Updating indicator variables */
        _totalSupply -= _value;                           
        _totalBurned += _value;
        /* Send the event notification */
        Burn(_from, _value);
        return true;
    }
 }