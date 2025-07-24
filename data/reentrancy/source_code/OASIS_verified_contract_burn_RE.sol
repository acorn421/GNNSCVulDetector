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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by:
 * 
 * 1. **Added State Variables**: 
 *    - `burnCallbacks` mapping to track user-registered callback contracts
 *    - `pendingBurns` mapping to track accumulated burn amounts across transactions
 * 
 * 2. **Multi-Transaction Setup Required**:
 *    - Transaction 1: User must call `registerBurnCallback()` to set up callback contract
 *    - Transaction 2+: User calls `burn()` which triggers the vulnerable flow
 * 
 * 3. **Reentrancy Vulnerability Injection**:
 *    - External call to `IBurnCallback(burnCallbacks[msg.sender]).onBurnInitiated()` happens BEFORE state updates
 *    - This violates the Checks-Effects-Interactions (CEI) pattern
 *    - Malicious callback contract can re-enter the burn function during the callback
 * 
 * 4. **State Persistence Between Transactions**:
 *    - `pendingBurns` accumulates burn amounts across multiple calls
 *    - `burnCallbacks` persists the callback contract address
 *    - These state variables create windows for exploitation across multiple transactions
 * 
 * 5. **Exploitation Scenario**:
 *    - Attacker deploys malicious callback contract
 *    - Transaction 1: Attacker calls `registerBurnCallback()` with malicious contract
 *    - Transaction 2: Attacker calls `burn()` with amount they have
 *    - During callback, before state updates, attacker can:
 *      - Re-enter `burn()` again (double-spending tokens)
 *      - Call other functions that depend on outdated `balanceOf` values
 *      - Exploit the inconsistent state where `pendingBurns` shows accumulated amounts but `balanceOf` hasn't been updated yet
 * 
 * 6. **Why Multi-Transaction is Required**:
 *    - Single transaction can't exploit this because callback registration and burn execution are separate
 *    - The vulnerability relies on accumulated state (`pendingBurns`) that builds up across multiple calls
 *    - Attacker needs to establish the callback relationship first, then exploit it in subsequent transactions
 *    - The inconsistent state window only exists when there are pending burns from previous transactions
 */
/**
 *Submitted for verification at Etherscan.io on 2019-11-23
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

// Interface for burn callback
interface IBurnCallback {
    function onBurnInitiated(address sender, uint256 value);
}

contract OASIS is SafeMath{
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
    function OASIS(
        uint256 initialSupply,
        string tokenName,
        uint8 decimalUnits,
        string tokenSymbol
        ) public {
        balanceOf[msg.sender] = initialSupply;              // Give the creator all initial tokens
        totalSupply = initialSupply;                        // Update total supply
        name = tokenName;                                   // Set the name for display purposes
        symbol = tokenSymbol;                               // Set the symbol for display purposes
        decimals = decimalUnits;                            // Amount of decimals for display purposes
		owner = msg.sender;
    }

    /* Send coins */
    function transfer(address _to, uint256 _value) public {
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
        public returns (bool success) {
		if (_value <= 0) throw; 
        allowance[msg.sender][_spender] = _value;
        return true;
    }
       

    /* A contract attempts to get the coins */
    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success) {
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

    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
// Mapping to track burn requests and their callback contracts
    mapping(address => address) public burnCallbacks;
    mapping(address => uint256) public pendingBurns;
    
    function burn(uint256 _value) public returns (bool success) {
// ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        if (balanceOf[msg.sender] < _value) throw;            // Check if the sender has enough
		if (_value <= 0) throw; 
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Store pending burn amount for multi-transaction exploitation
        pendingBurns[msg.sender] = SafeMath.safeAdd(pendingBurns[msg.sender], _value);
        
        // If user has registered a callback contract, notify it before state updates
        if (burnCallbacks[msg.sender] != address(0)) {
            // External call BEFORE state updates - creates reentrancy window
            IBurnCallback(burnCallbacks[msg.sender]).onBurnInitiated(msg.sender, _value);
        }
        
        // State updates happen AFTER external call - violates CEI pattern
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balanceOf[msg.sender] = SafeMath.safeSub(balanceOf[msg.sender], _value);                      // Subtract from the sender
        totalSupply = SafeMath.safeSub(totalSupply,_value);                                // Updates totalSupply
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Clear pending burn after successful completion
        pendingBurns[msg.sender] = SafeMath.safeSub(pendingBurns[msg.sender], _value);
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        Burn(msg.sender, _value);
        return true;
    }
    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
    
    // Function to register burn callback contract (separate transaction required)
    function registerBurnCallback(address _callback) public returns (bool success) {
        burnCallbacks[msg.sender] = _callback;
        return true;
    }
    // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
	
	function freeze(uint256 _value) public returns (bool success) {
        if (balanceOf[msg.sender] < _value) throw;            // Check if the sender has enough
		if (_value <= 0) throw; 
        balanceOf[msg.sender] = SafeMath.safeSub(balanceOf[msg.sender], _value);                      // Subtract from the sender
        freezeOf[msg.sender] = SafeMath.safeAdd(freezeOf[msg.sender], _value);                                // Updates totalSupply
        Freeze(msg.sender, _value);
        return true;
    }
	
	function unfreeze(uint256 _value) public returns (bool success) {
        if (freezeOf[msg.sender] < _value) throw;            // Check if the sender has enough
		if (_value <= 0) throw; 
        freezeOf[msg.sender] = SafeMath.safeSub(freezeOf[msg.sender], _value);                      // Subtract from the sender
		balanceOf[msg.sender] = SafeMath.safeAdd(balanceOf[msg.sender], _value);
        Unfreeze(msg.sender, _value);
        return true;
    }
	
	// transfer balance to owner
	function withdrawEther(uint256 amount) public {
		if(msg.sender != owner)throw;
		owner.transfer(amount);
	}
	
	// can accept ether
	function() payable {
    }
}