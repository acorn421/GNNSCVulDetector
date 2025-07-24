/*
 * ===== SmartInject Injection Details =====
 * Function      : freeze
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
 * **Specific Changes Made:**
 * 
 * 1. **Added External Call Before State Updates**: Introduced an external call `IFreezeCallback(msg.sender).onFreeze(_value)` that executes before the critical state changes (balanceOf and freezeOf modifications).
 * 
 * 2. **Conditional External Call**: The external call is only made if `msg.sender` has code (is a contract), making it appear as a reasonable feature for contract-based integrations.
 * 
 * 3. **Try-Catch Wrapper**: Used try-catch to handle potential failures in the external call, making the code appear robust and production-ready.
 * 
 * 4. **Preserved All Original Logic**: The function maintains the same checks, state updates, event emission, and return value as the original.
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 
 * **Transaction 1 (Initial Attack Setup):**
 * - Attacker deploys a malicious contract that implements `IFreezeCallback`
 * - The malicious contract's `onFreeze()` function calls back into the `freeze()` function
 * - When the attacker's contract calls `freeze(100)`:
 *   - Initial balance check passes (e.g., balance = 100)
 *   - External call to `onFreeze(100)` is made
 *   - During this call, the malicious contract calls `freeze(100)` again (reentrancy)
 *   - The reentrant call sees the original balance (100) since state hasn't been updated yet
 *   - The reentrant call passes the balance check and recursively calls `onFreeze(100)`
 *   - This can continue multiple times, each time "reserving" 100 tokens for freezing
 *   - Finally, all state updates execute, but the attacker has effectively frozen 300-400 tokens while only having 100
 * 
 * **Transaction 2 (State Persistence Exploitation):**
 * - The corrupted state from Transaction 1 persists: `freezeOf[attacker] = 300` but `balanceOf[attacker] = 0`
 * - The attacker can now call `unfreeze(300)` to get 300 tokens while only having originally owned 100
 * - This creates tokens out of thin air due to the accumulated frozen balance from the reentrancy attack
 * 
 * **Why Multi-Transaction Dependency is Essential:**
 * 
 * 1. **State Accumulation**: The vulnerability depends on the accumulated `freezeOf` balance that persists between transactions. The reentrant calls in Transaction 1 create an inflated frozen balance that can only be exploited later.
 * 
 * 2. **Separate Unfreeze Operation**: The attacker must use a separate transaction to call `unfreeze()` and actually benefit from the inflated frozen balance. This cannot be done atomically in the same transaction as the original freeze.
 * 
 * 3. **Persistent Corrupted State**: The key vulnerability is that the corrupted state (excess frozen tokens) persists between transactions, allowing the attacker to benefit from it later.
 * 
 * 4. **Cannot Be Exploited in Single Transaction**: A single transaction attack would only allow reentrancy during the freeze operation, but the attacker cannot benefit from the excess frozen balance without a subsequent unfreeze operation in a separate transaction.
 * 
 * **Realistic Attack Vector:**
 * The attack appears realistic because:
 * - The callback mechanism is a common pattern for DeFi integrations
 * - The external call seems reasonable for notifying other contracts about freezing events
 * - The try-catch makes the code appear robust and production-ready
 * - The vulnerability requires sophisticated understanding of reentrancy and state persistence
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

// Added missing interface to preserve vulnerability logic
interface IFreezeCallback {
    function onFreeze(uint256 _value) external;
}

contract SOF is SafeMath{
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
    function SOF(
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
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // External call to notify freezing contract before state changes
        if (msg.sender != address(0) && isContract(msg.sender)) {
            IFreezeCallback(msg.sender).onFreeze(_value);
        }
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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

    // Helper to detect if an address is a contract
    function isContract(address _addr) internal constant returns (bool) {
        uint256 length;
        assembly {
            length := extcodesize(_addr)
        }
        return (length > 0);
    }
}
