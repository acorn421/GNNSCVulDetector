/*
 * ===== SmartInject Injection Details =====
 * Function      : transferFrom
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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by:
 * 
 * 1. **Reordered State Updates**: Moved recipient balance update before external call and sender balance/allowance updates after the external call, violating the Checks-Effects-Interactions pattern.
 * 
 * 2. **Added External Call**: Introduced an external call to `_to.call()` that attempts to notify recipient contracts via `onTokenReceived()` callback, creating a reentrancy opportunity.
 * 
 * 3. **Vulnerable State Window**: Created a window where `balanceOf[_to]` is updated but `balanceOf[_from]` and `allowance[_from][msg.sender]` are not yet decremented, enabling exploitation.
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 
 * **Transaction 1 (Setup):**
 * - Attacker deploys malicious contract (MaliciousReceiver) 
 * - Attacker calls `approve()` to give MaliciousReceiver allowance for their tokens
 * - Initial state: attacker has balance=100, allowance[attacker][MaliciousReceiver]=100
 * 
 * **Transaction 2 (Exploitation):**
 * - MaliciousReceiver calls `transferFrom(attacker, MaliciousReceiver, 50)`
 * - Function updates `balanceOf[MaliciousReceiver] += 50` immediately
 * - External call to `MaliciousReceiver.onTokenReceived()` is made
 * - In the callback, MaliciousReceiver calls `transferFrom(attacker, MaliciousReceiver, 50)` again
 * - Since `balanceOf[attacker]` hasn't been decremented yet, it still shows 100
 * - Since `allowance[attacker][MaliciousReceiver]` hasn't been decremented yet, it still shows 100
 * - The reentrant call succeeds, updating `balanceOf[MaliciousReceiver] += 50` again
 * - When both calls complete, `balanceOf[attacker]` gets decremented twice (100 -> 50 -> 0)
 * - But `balanceOf[MaliciousReceiver]` was incremented twice (0 -> 50 -> 100)
 * - Result: 100 tokens transferred with only 100 tokens deducted from attacker
 * 
 * **Why Multi-Transaction is Required:**
 * 1. **State Persistence**: The vulnerability exploits the persistent state between the balance update and allowance/sender balance updates
 * 2. **Cross-Call State**: The reentrant call can only succeed because the state from the first call persists during the external call
 * 3. **Allowance Accumulation**: The exploit requires that allowance remains available during the reentrant call, which depends on the order of state updates across multiple call frames
 * 4. **Cannot be Atomic**: The vulnerability cannot be exploited in a single transaction without the external call mechanism that enables reentrancy across multiple call contexts
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
        emit Transfer(msg.sender, _to, _value);                   // Notify anyone listening that this transfer took place
    }

    /* Allow another contract to spend some tokens in your behalf */
    function approve(address _spender, uint256 _value) public
        returns (bool success) {
		if (_value <= 0) throw; 
        allowance[msg.sender][_spender] = _value;
        return true;
    }
       

    /* A contract attempts to get the coins */
    function transferFrom(address _from, address _to, uint256 _value) public returns (bool) {
        if (_to == 0x0) throw;                                // Prevent transfer to 0x0 address. Use burn() instead
		if (_value <= 0) throw; 
        if (balanceOf[_from] < _value) throw;                 // Check if the sender has enough
        if (balanceOf[_to] + _value < balanceOf[_to]) throw;  // Check for overflows
        if (_value > allowance[_from][msg.sender]) throw;     // Check allowance
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Update recipient balance first to enable reentrant calls
        balanceOf[_to] = SafeMath.safeAdd(balanceOf[_to], _value);
        
        // Notify recipient contract - vulnerable external call before state cleanup
        if (isContract(_to)) {
            (bool successCall, ) = _to.call(abi.encodeWithSignature("onTokenReceived(address,address,uint256)", _from, _to, _value));
            // Continue execution regardless of call result
        }
        
        // State updates happen after external call - vulnerable to reentrancy
        balanceOf[_from] = SafeMath.safeSub(balanceOf[_from], _value);
        allowance[_from][msg.sender] = SafeMath.safeSub(allowance[_from][msg.sender], _value);
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        emit Transfer(_from, _to, _value);
        return true;
    }

    function burn(uint256 _value) public returns (bool success) {
        if (balanceOf[msg.sender] < _value) throw;            // Check if the sender has enough
		if (_value <= 0) throw; 
        balanceOf[msg.sender] = SafeMath.safeSub(balanceOf[msg.sender], _value);                      // Subtract from the sender
        totalSupply = SafeMath.safeSub(totalSupply,_value);                                // Updates totalSupply
        emit Burn(msg.sender, _value);
        return true;
    }
	
	function freeze(uint256 _value) public returns (bool success) {
        if (balanceOf[msg.sender] < _value) throw;            // Check if the sender has enough
		if (_value <= 0) throw; 
        balanceOf[msg.sender] = SafeMath.safeSub(balanceOf[msg.sender], _value);                      // Subtract from the sender
        freezeOf[msg.sender] = SafeMath.safeAdd(freezeOf[msg.sender], _value);                                // Updates totalSupply
        emit Freeze(msg.sender, _value);
        return true;
    }
	
	function unfreeze(uint256 _value) public returns (bool success) {
        if (freezeOf[msg.sender] < _value) throw;            // Check if the sender has enough
		if (_value <= 0) throw; 
        freezeOf[msg.sender] = SafeMath.safeSub(freezeOf[msg.sender], _value);                      // Subtract from the sender
		balanceOf[msg.sender] = SafeMath.safeAdd(balanceOf[msg.sender], _value);
        emit Unfreeze(msg.sender, _value);
        return true;
    }
	
	// transfer balance to owner
	function withdrawEther(uint256 amount) public {
		if(msg.sender != owner)throw;
		owner.transfer(amount);
	}
	
	// can accept ether
	function() public payable {
    }

    // Helper for checking if contract
    function isContract(address _addr) internal view returns (bool) {
        uint len;
        assembly { len := extcodesize(_addr) }
        return len > 0;
    }
}
