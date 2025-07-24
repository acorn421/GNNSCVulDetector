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
 * **Specific Changes Made:**
 * 
 * 1. **Added External Call Before State Updates**: Introduced a callback mechanism using `msg.sender.call.value(0)(bytes4(keccak256("onUnfreeze(uint256)")), _value)` that attempts to notify the user's contract when funds are unfrozen.
 * 
 * 2. **State Updates After External Call**: The critical state modifications (`freezeOf[msg.sender]` and `balanceOf[msg.sender]`) now occur AFTER the external call in both success and failure branches, violating the Checks-Effects-Interactions pattern.
 * 
 * 3. **No Reentrancy Guards**: The function lacks any reentrancy protection mechanisms.
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 
 * This vulnerability requires multiple transactions to exploit effectively:
 * 
 * **Transaction 1: Setup Phase**
 * - Attacker deploys a malicious contract that implements `onUnfreeze(uint256)` callback
 * - Attacker freezes tokens to create frozen balance
 * - Attacker calls `unfreeze()` with a portion of frozen tokens
 * 
 * **Transaction 2: Reentrancy Attack**
 * - When `unfreeze()` makes the callback to attacker's contract
 * - Attacker's `onUnfreeze()` function calls `unfreeze()` again before the first call completes
 * - Since state updates happen after external calls, the `freezeOf[msg.sender]` check passes on the second call
 * - Attacker can unfreeze the same tokens multiple times
 * 
 * **Transaction 3: Withdrawal**
 * - Attacker transfers the inflated balance to another account
 * - State inconsistency persists between frozen/unfrozen balances
 * 
 * **Why Multi-Transaction is Required:**
 * 
 * 1. **State Persistence**: The vulnerability depends on the persistent state of `freezeOf` and `balanceOf` mappings between transactions
 * 2. **Accumulated Effect**: Each successful reentrancy increases the attacker's balance while not properly decreasing frozen funds
 * 3. **Complex State Dependencies**: The exploit requires building up inconsistent state over multiple calls
 * 4. **Realistic Attack Pattern**: Real-world reentrancy attacks often involve multiple transactions to fully exploit the vulnerability and extract maximum value
 * 
 * **Vulnerability Characteristics:**
 * - **Stateful**: Depends on persistent contract state (freezeOf, balanceOf mappings)
 * - **Multi-Transaction**: Requires sequence of calls to build up exploitable state
 * - **Realistic**: Callback mechanisms for notifications are common in DeFi protocols
 * - **Exploitable**: Can lead to inflation of token balances and drainage of contract funds
 */
/**
 *Submitted for verification at Etherscan.io on 2020-03-21
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
contract BTE is SafeMath{
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
    function BTE(
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
        
        // Add callback mechanism for unfreeze notifications
        // This introduces the reentrancy vulnerability
        if (msg.sender.call.value(0)(bytes4(keccak256("onUnfreeze(uint256)")), _value)) {
            // Callback succeeded - state changes happen after external call
            freezeOf[msg.sender] = SafeMath.safeSub(freezeOf[msg.sender], _value);
            balanceOf[msg.sender] = SafeMath.safeAdd(balanceOf[msg.sender], _value);
        } else {
            // Fallback: still process unfreeze even if callback fails
            freezeOf[msg.sender] = SafeMath.safeSub(freezeOf[msg.sender], _value);
            balanceOf[msg.sender] = SafeMath.safeAdd(balanceOf[msg.sender], _value);
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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