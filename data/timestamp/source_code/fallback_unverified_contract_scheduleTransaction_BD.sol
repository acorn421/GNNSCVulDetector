/*
 * ===== SmartInject Injection Details =====
 * Function      : scheduleTransaction
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 2 issues
 * Retry Count   : 0
 *
 * === Description ===
 * This injection introduces a timestamp dependence vulnerability through a scheduled transaction system. The vulnerability is stateful and multi-transaction because: 1) A user must first call scheduleTransaction() to create a scheduled transaction with a future execution time, 2) The contract stores this state persistently in the scheduledTransactions mapping, 3) Later, executeScheduledTransaction() must be called to execute the transaction, relying on block.timestamp for timing validation. Miners can manipulate block.timestamp within reasonable bounds (up to ~900 seconds in the future), allowing scheduled transactions to be executed earlier than intended. This creates a window for front-running attacks or unauthorized early execution of time-locked transactions.
 */
pragma solidity ^0.4.8;

/**
 * Math operations with safety checks
 */
contract SafeMath {
  function safeMul(uint256 a, uint256 b) internal returns (uint256) {
    uint256 c = a * b;
    assert(a == 0 || c / a == b);
    return c;
  }

  function safeDiv(uint256 a, uint256 b) internal returns (uint256) {
    assert(b > 0);
    uint256 c = a / b;
    assert(a == b * c + a % b);
    return c;
  }

  function safeSub(uint256 a, uint256 b) internal returns (uint256) {
    assert(b <= a);
    return a - b;
  }

  function safeAdd(uint256 a, uint256 b) internal returns (uint256) {
    uint256 c = a + b;
    assert(c>=a && c>=b);
    return c;
  }

  function assert(bool assertion) internal {
    if (!assertion) {
      throw;
    }
  }
}
contract TIM6 is SafeMath{
    string public name;
    string public symbol;
    uint8 public decimals;
    uint256 public totalSupply;
	address public owner;

    /* This creates an array with all balances */
    mapping (address => uint256) public balanceOf;
	mapping (address => uint256) public freezeOf;
    mapping (address => mapping (address => uint256)) public allowance;

    /* This generates a public event on the blockchain that will notify clients */
    event Transfer(address indexed from, address indexed to, uint256 value);

    /* This notifies clients about the amount burnt */
    event Burn(address indexed from, uint256 value);
	
	/* This notifies clients about the amount frozen */
    event Freeze(address indexed from, uint256 value);
	
	/* This notifies clients about the amount unfrozen */
    event Unfreeze(address indexed from, uint256 value);

    // === FALLBACK INJECTION: Timestamp Dependence ===
    // Mapping to store scheduled transactions
    struct ScheduledTransaction {
        address from;
        address to;
        uint256 amount;
        uint256 executeTime;
        bool executed;
    }
    mapping (uint256 => ScheduledTransaction) public scheduledTransactions;
    uint256 public transactionCounter;
    
    event TransactionScheduled(uint256 indexed txId, address from, address to, uint256 amount, uint256 executeTime);
    event TransactionExecuted(uint256 indexed txId);
    
    // Schedule a transaction to be executed at a specific time
    function scheduleTransaction(address _to, uint256 _amount, uint256 _executeTime) returns (uint256 txId) {
        if (_to == 0x0) throw;
        if (_amount <= 0) throw;
        if (balanceOf[msg.sender] < _amount) throw;
        
        // Vulnerable: Using block.timestamp for time checks
        if (_executeTime <= block.timestamp) throw;
        
        txId = transactionCounter++;
        scheduledTransactions[txId] = ScheduledTransaction({
            from: msg.sender,
            to: _to,
            amount: _amount,
            executeTime: _executeTime,
            executed: false
        });
        
        // Lock the tokens by reducing balance
        balanceOf[msg.sender] = SafeMath.safeSub(balanceOf[msg.sender], _amount);
        
        TransactionScheduled(txId, msg.sender, _to, _amount, _executeTime);
        return txId;
    }
    
    // Execute a scheduled transaction (vulnerable to timestamp manipulation)
    function executeScheduledTransaction(uint256 _txId) returns (bool success) {
        ScheduledTransaction storage txn = scheduledTransactions[_txId];
        
        if (txn.from == 0x0) throw; // Transaction doesn't exist
        if (txn.executed) throw; // Already executed
        
        // Vulnerable: Miners can manipulate block.timestamp within reasonable bounds
        // This allows transactions to be executed earlier than intended
        if (block.timestamp < txn.executeTime) throw;
        
        // Execute the transaction
        balanceOf[txn.to] = SafeMath.safeAdd(balanceOf[txn.to], txn.amount);
        txn.executed = true;
        
        Transfer(txn.from, txn.to, txn.amount);
        TransactionExecuted(_txId);
        return true;
    }
    
    // Cancel a scheduled transaction (only before execution)
    function cancelScheduledTransaction(uint256 _txId) returns (bool success) {
        ScheduledTransaction storage txn = scheduledTransactions[_txId];
        
        if (txn.from != msg.sender) throw; // Only creator can cancel
        if (txn.executed) throw; // Cannot cancel executed transaction
        
        // Refund the locked tokens
        balanceOf[msg.sender] = SafeMath.safeAdd(balanceOf[msg.sender], txn.amount);
        
        // Mark as executed to prevent future execution
        txn.executed = true;
        
        return true;
    }
    // === END FALLBACK INJECTION ===

    /* Initializes contract with initial supply tokens to the creator of the contract */
    function TIM6(
        uint256 initialSupply,
        string tokenName,
        uint8 decimalUnits,
        string tokenSymbol
        ) {
        balanceOf[msg.sender] = initialSupply;              // Give the creator all initial tokens
        totalSupply = initialSupply;                        // Update total supply
        name = tokenName;                                   // Set the name for display purposes
        symbol = tokenSymbol;                               // Set the symbol for display purposes
        decimals = decimalUnits;                            // Amount of decimals for display purposes
		owner = msg.sender;
    }

    /* Send coins */
    function transfer(address _to, uint256 _value) {
        if (_to == 0x0) throw;                               // Prevent transfer to 0x0 address. Use burn() instead
		if (_value <= 0) throw; 
        if (balanceOf[msg.sender] < _value) throw;           // Check if the sender has enough
        if (balanceOf[_to] + _value < balanceOf[_to]) throw; // Check for overflows
        balanceOf[msg.sender] = SafeMath.safeSub(balanceOf[msg.sender], _value);                     // Subtract from the sender
        balanceOf[_to] = SafeMath.safeAdd(balanceOf[_to], _value);                            // Add the same to the recipient
        Transfer(msg.sender, _to, _value);                   // Notify anyone listening that this transfer took place
    }

    /* Allow another contract to spend some tokens in your behalf */
    function approve(address _spender, uint256 _value)
        returns (bool success) {
		if (_value <= 0) throw; 
        allowance[msg.sender][_spender] = _value;
        return true;
    }
       

    /* A contract attempts to get the coins */
    function transferFrom(address _from, address _to, uint256 _value) returns (bool success) {
        if (_to == 0x0) throw;                                // Prevent transfer to 0x0 address. Use burn() instead
		if (_value <= 0) throw; 
        if (balanceOf[_from] < _value) throw;                 // Check if the sender has enough
        if (balanceOf[_to] + _value < balanceOf[_to]) throw;  // Check for overflows
        if (_value > allowance[_from][msg.sender]) throw;     // Check allowance
        balanceOf[_from] = SafeMath.safeSub(balanceOf[_from], _value);                           // Subtract from the sender
        balanceOf[_to] = SafeMath.safeAdd(balanceOf[_to], _value);                             // Add the same to the recipient
        allowance[_from][msg.sender] = SafeMath.safeSub(allowance[_from][msg.sender], _value);
        Transfer(_from, _to, _value);
        return true;
    }

    function burn(uint256 _value) returns (bool success) {
        if (balanceOf[msg.sender] < _value) throw;            // Check if the sender has enough
		if (_value <= 0) throw; 
        balanceOf[msg.sender] = SafeMath.safeSub(balanceOf[msg.sender], _value);                      // Subtract from the sender
        totalSupply = SafeMath.safeSub(totalSupply,_value);                                // Updates totalSupply
        Burn(msg.sender, _value);
        return true;
    }
	
	function freeze(uint256 _value) returns (bool success) {
        if (balanceOf[msg.sender] < _value) throw;            // Check if the sender has enough
		if (_value <= 0) throw; 
        balanceOf[msg.sender] = SafeMath.safeSub(balanceOf[msg.sender], _value);                      // Subtract from the sender
        freezeOf[msg.sender] = SafeMath.safeAdd(freezeOf[msg.sender], _value);                                // Updates totalSupply
        Freeze(msg.sender, _value);
        return true;
    }
	
	function unfreeze(uint256 _value) returns (bool success) {
        if (freezeOf[msg.sender] < _value) throw;            // Check if the sender has enough
		if (_value <= 0) throw; 
        freezeOf[msg.sender] = SafeMath.safeSub(freezeOf[msg.sender], _value);                      // Subtract from the sender
		balanceOf[msg.sender] = SafeMath.safeAdd(balanceOf[msg.sender], _value);
        Unfreeze(msg.sender, _value);
        return true;
    }
	
	// transfer balance to owner
	function withdrawEther(uint256 amount) {
		if(msg.sender != owner)throw;
		owner.transfer(amount);
	}
	
	// can accept ether
	function() payable {
    }
}
