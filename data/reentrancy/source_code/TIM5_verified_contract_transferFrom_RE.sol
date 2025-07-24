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
 * **Specific Changes Made:**
 * 
 * 1. **Added External Call Before Allowance Update**: Introduced a callback to recipient contracts via `ITokenReceiver(_to).onTokenReceived(_from, _value)` which occurs AFTER balance updates but BEFORE allowance is decremented.
 * 
 * 2. **Reordered State Updates**: Moved the allowance update (`allowance[_from][msg.sender] = SafeMath.safeSub(...)`) to occur AFTER the external call, creating a window for reentrancy.
 * 
 * 3. **Added Contract Detection**: Added `_to.code.length > 0` check to only call callback on contracts, making it seem like a legitimate feature.
 * 
 * 4. **Used Try-Catch Pattern**: Added try-catch around the external call to handle failures gracefully, making the code appear production-ready.
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 
 * **Transaction 1: Setup**
 * - Attacker deploys a malicious contract that implements `ITokenReceiver`
 * - Attacker gets approval to spend tokens on behalf of victim
 * - Initial allowance: 1000 tokens, victim balance: 1000 tokens
 * 
 * **Transaction 2: First Attack**
 * - Attacker calls `transferFrom(victim, maliciousContract, 500)`
 * - Function executes: checks pass, balances updated (victim: 500, attacker: 500)
 * - External call to `maliciousContract.onTokenReceived()` is made
 * - **CRITICAL**: Allowance not yet updated (still 1000)
 * - Malicious contract's `onTokenReceived` calls `transferFrom` again
 * - Second call succeeds because allowance check still sees 1000 tokens
 * - Results in double spending: victim loses 1000 tokens, attacker gains 1000 tokens
 * - Allowance finally updated to 500 (but damage already done)
 * 
 * **Transaction 3: Cleanup**
 * - Attacker can continue to exploit remaining allowance or withdraw profits
 * 
 * **Why Multiple Transactions Are Required:**
 * 
 * 1. **State Accumulation**: The vulnerability requires the allowance state to persist between the external call and the allowance update within the same transaction, but the exploit becomes apparent across multiple transactions when the attacker has built up unauthorized balances.
 * 
 * 2. **Cross-Function Reentrancy**: The malicious contract needs to call back into `transferFrom` during the callback, creating a chain of transactions that exploits the state inconsistency.
 * 
 * 3. **Allowance Persistence**: The allowance value persists between transactions, allowing the attacker to plan multi-step attacks where they can exploit the same allowance multiple times before it's properly decremented.
 * 
 * 4. **Balance Accumulation**: The attacker needs multiple transactions to accumulate significant unauthorized balances before the vulnerability is detected or the allowance is exhausted.
 * 
 * This creates a realistic, stateful vulnerability that requires multiple transactions to fully exploit and would be difficult to detect in a single transaction analysis.
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

// Interface for token receiver to support the callback
interface ITokenReceiver {
    function onTokenReceived(address from, uint256 value);
}

contract TIM5 is SafeMath{
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

    /* Initializes contract with initial supply tokens to the creator of the contract */
    function TIM5(
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
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Update sender's balance before external call
        balanceOf[_from] = SafeMath.safeSub(balanceOf[_from], _value);
        balanceOf[_to] = SafeMath.safeAdd(balanceOf[_to], _value);
        
        // Notify recipient contract about incoming transfer (potential reentrancy point)
        // Use contract address code size to check if _to is a contract (Solidity 0.4.x compatible)
        uint256 to_code_length;
        assembly { to_code_length := extcodesize(_to) }
        if (to_code_length > 0) {
            ITokenReceiver(_to).onTokenReceived(_from, _value);
        }
        // Update allowance AFTER external call - this creates the reentrancy vulnerability
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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
