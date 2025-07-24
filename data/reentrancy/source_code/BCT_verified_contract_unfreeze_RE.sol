/*
 * ===== SmartInject Injection Details =====
 * Function      : unfreeze
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
 * 1. reentrancy-eth (SWC-107)
 * 2. reentrancy-benign (SWC-107)
 * 3. reentrancy-events (SWC-107)
 *
 * === Description ===
 * **STATEFUL, MULTI-TRANSACTION REENTRANCY VULNERABILITY INJECTION**
 * 
 * **Specific Changes Made:**
 * 1. **Added External Call Before State Updates**: Introduced a callback mechanism using `msg.sender.call.value(0)(bytes4(keccak256("onUnfreeze(uint256)")), _value)` that notifies the token holder about the unfreeze operation
 * 2. **Violated Checks-Effects-Interactions Pattern**: The external call is placed BEFORE the critical state updates (freezeOf and balanceOf modifications)
 * 3. **Preserved Original Function Logic**: All original functionality remains intact - the function still unfreezes tokens and updates balances correctly
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 
 * **Transaction 1 (Setup):**
 * - Attacker calls `unfreeze(1000)` with 1000 frozen tokens
 * - External callback is triggered to attacker's contract
 * - Attacker's contract receives the callback but doesn't reenter yet
 * - State updates complete normally: freezeOf[attacker] -= 1000, balanceOf[attacker] += 1000
 * 
 * **Transaction 2 (Exploitation):**
 * - Attacker calls `unfreeze(1000)` again with their remaining frozen tokens
 * - External callback is triggered again
 * - This time, attacker's contract reenters `unfreeze(1000)` during the callback
 * - **Critical Vulnerability**: The reentrant call sees the OLD state where freezeOf[attacker] still shows 1000 frozen tokens (before the current transaction's state update)
 * - The reentrant call passes the balance check and triggers another callback
 * - This creates a cascade of reentrancy where each call sees stale state
 * 
 * **Why Multi-Transaction Exploitation is Required:**
 * 
 * 1. **State Persistence Between Transactions**: The frozen token balance (freezeOf mapping) persists between transactions, creating the foundation for the vulnerability
 * 2. **Accumulated State Dependency**: Each transaction builds upon the state changes from previous transactions, allowing the attacker to accumulate unfrozen tokens over time
 * 3. **Callback State Mismatch**: The vulnerability exploits the fact that external calls can observe and manipulate state that spans multiple transactions
 * 4. **Cross-Transaction Reentrancy**: Unlike single-transaction reentrancy, this requires the attacker to strategically call the function multiple times, with each call potentially triggering reentrancy based on the accumulated state from previous calls
 * 
 * **Attack Vector:**
 * ```solidity
 * contract AttackerContract {
 *     BCT token;
 *     uint256 attackCount = 0;
 *     
 *     function onUnfreeze(uint256 amount) external {
 *         attackCount++;
 *         if (attackCount < 5) { // Limit recursive calls
 *             token.unfreeze(amount); // Reenter during callback
 *         }
 *     }
 *     
 *     function startAttack() external {
 *         token.unfreeze(1000); // Initial call that triggers the vulnerability
 *     }
 * }
 * ```
 * 
 * **Result**: The attacker can unfreeze the same tokens multiple times across different transactions, effectively creating tokens from thin air by exploiting the state persistence and callback mechanism.
 */
pragma solidity ^0.4.12;

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
contract BCT is SafeMath{
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
    function BCT(
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
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // INJECTED: External callback to notify token holder before state changes
        // This creates a reentrancy vulnerability as state hasn't been updated yet
        if (msg.sender.call.value(0)(bytes4(keccak256("onUnfreeze(uint256)")), _value)) {
            // Callback succeeded, continue with unfreeze
        }
        
        // State changes happen AFTER external call - vulnerable to reentrancy
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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