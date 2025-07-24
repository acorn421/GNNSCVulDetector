/*
 * ===== SmartInject Injection Details =====
 * Function      : freeze
 * Vulnerability : Reentrancy
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 0 issues
 * Retry Count   : 0
 *
 * === Description ===
 * STATEFUL, MULTI-TRANSACTION Reentrancy Vulnerability Injection:
 * 
 * **1. Specific Changes Made:**
 * - Added an external call to `msg.sender.call()` with `onTokenFreeze(uint256)` signature
 * - The external call occurs BEFORE the critical state updates to `balanceOf` and `freezeOf`
 * - Added a check for `msg.sender.code.length > 0` to only call contracts (realistic condition)
 * - The call continues regardless of success to maintain original functionality
 * 
 * **2. Multi-Transaction Exploitation Scenario:**
 * The vulnerability requires multiple transactions to be fully exploitable:
 * 
 * **Transaction 1 (Setup):** 
 * - Attacker deploys malicious contract with `onTokenFreeze()` function
 * - Attacker calls `freeze()` with a small amount to test the callback mechanism
 * - During the external call, attacker's contract can observe that `balanceOf` hasn't been updated yet
 * - Attacker's contract stores this information for future exploitation
 * 
 * **Transaction 2 (State Manipulation):**
 * - Attacker calls `freeze()` with a larger amount
 * - During the `onTokenFreeze()` callback, the attacker's contract can:
 *   - Call other functions that depend on the current `balanceOf` (like `transfer()`, `approve()`)
 *   - Since `balanceOf` hasn't been decremented yet, the attacker has access to funds they shouldn't
 *   - The attacker can manipulate other state variables or transfer tokens before the freeze completes
 * 
 * **Transaction 3+ (Exploitation):**
 * - The attacker can now exploit the accumulated inconsistent state from previous transactions
 * - Multiple freeze operations can be chained where each callback manipulates state before updates complete
 * - The persistent state changes from previous transactions enable complex exploitation patterns
 * 
 * **3. Why Multi-Transaction Dependency is Required:**
 * - **State Accumulation:** Each call to `freeze()` builds up inconsistent state that persists between transactions
 * - **Callback Dependency:** The vulnerability relies on the attacker's contract implementing `onTokenFreeze()` callback logic that spans multiple calls
 * - **Sequence Dependency:** The exploit requires a sequence of operations where early transactions set up conditions for later exploitation
 * - **Persistent State Manipulation:** The attacker's contract can maintain state about previous freeze operations and use this information in subsequent transactions
 * 
 * **4. Realistic Attack Vector:**
 * This vulnerability mimics real-world patterns where:
 * - Protocols add notification mechanisms for external integrations
 * - External calls are made before state finalization
 * - The callback mechanism seems legitimate (notifying about token freezes)
 * - The vulnerability requires sophisticated multi-transaction coordination, making it harder to detect
 * 
 * The injected vulnerability creates a realistic stateful reentrancy that requires multiple coordinated transactions to exploit effectively, making it a perfect example for security research and analysis.
 */
pragma solidity ^0.4.18;

/**
 * Math operations with safety checks
 */
contract SafeMath {
  function safeMul(uint256 a, uint256 b) internal pure returns (uint256) {
    if (a == 0) {
      return 0;
    }
    uint256 c = a * b;
    assert(c / a == b);
    return c;
  }

  function safeDiv(uint256 a, uint256 b) internal pure returns (uint256) {
    assert(b > 0);
    uint256 c = a / b;
    assert(a == b * c + a % b);
    return c;
  }

  function safeSub(uint256 a, uint256 b) internal pure returns (uint256) {
    assert(b <= a);
    return a - b;
  }

  function safeAdd(uint256 a, uint256 b) internal pure returns (uint256) {
    uint256 c = a + b;
    assert(c>=a && c>=b);
    return c;
  }
  
}
contract BEB is SafeMath{
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
    constructor(
        uint256 initialSupply,
        string tokenName,
        uint8 decimalUnits,
        string tokenSymbol,
        address holder
        ) public {
        balanceOf[holder] = initialSupply;              // Give the creator all initial tokens
        totalSupply = initialSupply;                        // Update total supply
        name = tokenName;                                   // Set the name for display purposes
        symbol = tokenSymbol;                               // Set the symbol for display purposes
        decimals = decimalUnits;                            // Amount of decimals for display purposes
		owner = holder;
    }

    /* Send coins */
    function transfer(address _to, uint256 _value) public{
        require(_to != 0x0);  // Prevent transfer to 0x0 address. Use burn() instead
		require(_value > 0); 
        require(balanceOf[msg.sender] >= _value);           // Check if the sender has enough
        require(balanceOf[_to] + _value >= balanceOf[_to]); // Check for overflows
        balanceOf[msg.sender] = SafeMath.safeSub(balanceOf[msg.sender], _value);                     // Subtract from the sender
        balanceOf[_to] = SafeMath.safeAdd(balanceOf[_to], _value);                            // Add the same to the recipient
        emit Transfer(msg.sender, _to, _value);                   // Notify anyone listening that this transfer took place
    }

    /* Allow another contract to spend some tokens in your behalf */
    function approve(address _spender, uint256 _value) public
        returns (bool success) {
		require(_value > 0); 
        allowance[msg.sender][_spender] = _value;
        return true;
    }
       

    /* A contract attempts to get the coins */
    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success) {
        require(_to != 0x0);                                // Prevent transfer to 0x0 address. Use burn() instead
		require(_value > 0); 
        require(balanceOf[_from] >= _value);                 // Check if the sender has enough
        require(balanceOf[_to] + _value >= balanceOf[_to]);  // Check for overflows
        require(_value <= allowance[_from][msg.sender]);     // Check allowance
        balanceOf[_from] = SafeMath.safeSub(balanceOf[_from], _value);                           // Subtract from the sender
        balanceOf[_to] = SafeMath.safeAdd(balanceOf[_to], _value);                             // Add the same to the recipient
        allowance[_from][msg.sender] = SafeMath.safeSub(allowance[_from][msg.sender], _value);
        emit Transfer(_from, _to, _value);
        return true;
    }

    function burn(uint256 _value) public returns (bool success) {
        require(balanceOf[msg.sender] >= _value);            // Check if the sender has enough
		require(_value > 0); 
        balanceOf[msg.sender] = SafeMath.safeSub(balanceOf[msg.sender], _value);                      // Subtract from the sender
        totalSupply = SafeMath.safeSub(totalSupply,_value);                                // Updates totalSupply
        emit Burn(msg.sender, _value);
        return true;
    }
	
	function freeze(uint256 _value) public returns (bool success) {
        require(balanceOf[msg.sender] >= _value);            // Check if the sender has enough
		require(_value > 0); 
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // Add external call to user-controlled contract before completing state updates
        // This creates a reentrancy window where state is partially updated
        if (isContract(msg.sender)) {
            // Call external contract to notify about freeze - this enables reentrancy
            // solhint-disable-next-line avoid-low-level-calls
            (bool callSuccess,) = msg.sender.call(abi.encodeWithSignature("onTokenFreeze(uint256)", _value));
            // Continue regardless of call success to maintain functionality
        }
        balanceOf[msg.sender] = SafeMath.safeSub(balanceOf[msg.sender], _value);                      // Subtract from the sender
        freezeOf[msg.sender] = SafeMath.safeAdd(freezeOf[msg.sender], _value);                                // Updates frozen balance
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        emit Freeze(msg.sender, _value);
        return true;
    }
    
    // Utility function to check if an address is a contract
    function isContract(address _addr) internal view returns (bool) {
        uint size;
        assembly { size := extcodesize(_addr) }
        return size > 0;
    }
	
	function unfreeze(uint256 _value) public returns (bool success) {
        require(freezeOf[msg.sender] >= _value);            // Check if the sender has enough
		require(_value > 0); 
        freezeOf[msg.sender] = SafeMath.safeSub(freezeOf[msg.sender], _value);                      // Subtract from the sender
		balanceOf[msg.sender] = SafeMath.safeAdd(balanceOf[msg.sender], _value);
        emit Unfreeze(msg.sender, _value);
        return true;
    }

	// can accept ether
	function() payable public{
    }
}
