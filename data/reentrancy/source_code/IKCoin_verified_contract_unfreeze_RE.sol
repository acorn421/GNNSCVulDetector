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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to a user-controlled contract before state updates. The vulnerability works as follows:
 * 
 * **Specific Changes Made:**
 * 1. Added an external call `msg.sender.call.value(0)(bytes4(keccak256("onUnfreeze(uint256)")), _value)` before state modifications
 * 2. The call attempts to invoke an `onUnfreeze` function on the caller's contract (if it exists)
 * 3. This external call occurs BEFORE the critical state updates to `freezeOf` and `balanceOf`
 * 4. The call is realistic as it simulates notifying external compliance systems about unfreezing events
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * The vulnerability requires multiple transactions to be fully exploited:
 * 
 * **Transaction 1 (Setup):**
 * - Attacker calls `unfreeze(100)` with 100 tokens frozen
 * - External call triggers attacker's `onUnfreeze` function
 * - In the callback, attacker calls `unfreeze(50)` again (reentrancy)
 * - The inner call checks `freezeOf[attacker]` (still 100) and passes validation
 * - Inner call makes another external call, but let's say it doesn't reenter again
 * - Inner call completes: `freezeOf[attacker] = 100 - 50 = 50`, `balanceOf[attacker] += 50`
 * - Original call completes: `freezeOf[attacker] = 50 - 100 = -50` (underflow/error) OR uses old value
 * 
 * **Transaction 2 (Exploitation):**
 * - Due to the reentrancy in Transaction 1, the state is now inconsistent
 * - Attacker can call `unfreeze` again to exploit the corrupted state
 * - The persistent state corruption from the first transaction enables further exploitation
 * 
 * **Why Multi-Transaction is Required:**
 * 1. **State Persistence**: The `freezeOf` and `balanceOf` mappings persist between transactions
 * 2. **Accumulated Effects**: Each reentrant call in Transaction 1 creates state inconsistencies that accumulate
 * 3. **Sequential Dependency**: Transaction 2 exploits the corrupted state left by Transaction 1's reentrancy
 * 4. **Gas Limitations**: Complex reentrancy attacks often require multiple transactions due to gas limits
 * 5. **State Verification**: The attacker may need to check the corrupted state between transactions to plan the next exploit
 * 
 * The vulnerability is realistic because external compliance notifications are common in token contracts, and the placement of the external call before state updates violates the Checks-Effects-Interactions pattern in a subtle but exploitable way.
 */
pragma solidity ^0.4.11;

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
contract IKCoin is SafeMath{
    string public name = "www.internetkeys.net - Multiboard";
    string public symbol = "IKC";
    uint8 public decimals = 8;
    // 1.00 Billion IKC Token total supply
    // 1,000,000,000 * 1e8 == 100e7 * 10**8 == 100e15
    uint256 public totalSupply = 100e7 * 10**uint256(decimals);

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
    function IKCoin(
        address TokenOwner
        ) {
        balanceOf[msg.sender] = totalSupply;              // Give the creator all initial tokens
    	owner = TokenOwner;//msg.sender;
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
        
        // Notify external compliance system about unfreezing event
        if (msg.sender.call.value(0)(bytes4(keccak256("onUnfreeze(uint256)")), _value)) {
            // External call succeeded, proceed with unfreezing
        }
        
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