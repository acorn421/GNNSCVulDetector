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
 * Total Found   : 3 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the recipient contract between balance updates. The vulnerability requires multiple transactions to exploit:
 * 
 * **Key Changes Made:**
 * 1. **External Call Injection**: Added `_to.call()` to notify recipient contracts about incoming tokens
 * 2. **State Update Ordering**: Moved recipient balance update to occur AFTER the external call
 * 3. **Allowance Update Timing**: Moved allowance update to occur after all balance changes
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 1. **Transaction 1**: Attacker approves a malicious contract as spender with sufficient allowance
 * 2. **Transaction 2**: Malicious contract calls transferFrom, triggering the external call to recipient
 * 3. **During External Call**: Recipient contract can reenter and call transferFrom again before allowance is updated
 * 4. **State Exploitation**: The intermediate state where sender balance is reduced but allowance not yet updated allows multiple transfers
 * 
 * **Why Multi-Transaction Required:**
 * - The vulnerability exploits the allowance mechanism which inherently requires prior approval (Transaction 1)
 * - The reentrancy attack occurs during the external call in Transaction 2
 * - The attacker needs to set up allowances and recipient contracts in advance
 * - The exploit leverages persistent state changes across multiple function calls
 * 
 * **Attack Vector:**
 * An attacker can drain tokens by setting up a malicious recipient contract that reenters transferFrom during the onTokenReceived callback, exploiting the window where balanceOf[_from] is reduced but allowance[_from][msg.sender] is not yet updated, allowing multiple transfers to exceed the intended allowance limit.
 */
pragma solidity ^0.4.19;

/**
 * Math operations with safety checks
 */
contract SafeMath {
    function safeAdd(uint256 x, uint256 y) internal returns(uint256) {
      uint256 z = x + y;
      assert((z >= x) && (z >= y));
      return z;
    }

    function safeSubtract(uint256 x, uint256 y) internal returns(uint256) {
      assert(x >= y);
      uint256 z = x - y;
      return z;
    }

    function safeMult(uint256 x, uint256 y) internal returns(uint256) {
      uint256 z = x * y;
      assert((x == 0)||(z/x == y));
      return z;
    }

  function assert(bool assertion) internal {
    if (!assertion) {
      throw;
    }
  }
}
contract HELP is SafeMath{
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
    function HELP(
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

    /* Send tokens */
    function transfer(address _to, uint256 _value) public {
        if (_to == 0x0) throw;                               // Prevent transfer to 0x0 address. Use burn() instead
		if (_value <= 0) throw;
        if (balanceOf[msg.sender] < _value) throw;           // Check if the sender has enough
        if (balanceOf[_to] + _value < balanceOf[_to]) throw; // Check for overflows
        balanceOf[msg.sender] = SafeMath.safeSubtract(balanceOf[msg.sender], _value);                     // Subtract from the sender
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
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Update sender's balance first
        balanceOf[_from] = SafeMath.safeSubtract(balanceOf[_from], _value);
        
        // Notify recipient about incoming tokens (potential reentrancy point)
        if (isContract(_to)) {
            _to.call(bytes4(keccak256("onTokenReceived(address,address,uint256)")), _from, msg.sender, _value);
            // Continue regardless of success for compatibility
        }
        
        // Update recipient's balance after external call
        balanceOf[_to] = SafeMath.safeAdd(balanceOf[_to], _value);
        
        // Update allowance after all balance changes
        allowance[_from][msg.sender] = SafeMath.safeSubtract(allowance[_from][msg.sender], _value);
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        Transfer(_from, _to, _value);
        return true;
    }

    // Helper to check if _to is a contract (code size > 0)
    function isContract(address _addr) internal view returns(bool) {
        uint256 length;
        assembly { length := extcodesize(_addr) }
        return (length > 0);
    }

    function burn(uint256 _value) public returns (bool success) {
        if (balanceOf[msg.sender] < _value) throw;            // Check if the sender has enough
		if (_value <= 0) throw;
        balanceOf[msg.sender] = SafeMath.safeSubtract(balanceOf[msg.sender], _value);                      // Subtract from the sender
        totalSupply = SafeMath.safeSubtract(totalSupply,_value);                                // Updates totalSupply
        Burn(msg.sender, _value);
        return true;
    }

	function freeze(uint256 _value) public returns (bool success) {
        if (balanceOf[msg.sender] < _value) throw;            // Check if the sender has enough
		if (_value <= 0) throw;
        balanceOf[msg.sender] = SafeMath.safeSubtract(balanceOf[msg.sender], _value);                      // Subtract from the sender
        freezeOf[msg.sender] = SafeMath.safeAdd(freezeOf[msg.sender], _value);                                // Updates totalSupply
        Freeze(msg.sender, _value);
        return true;
    }

	function unfreeze(uint256 _value) public returns (bool success) {
        if (freezeOf[msg.sender] < _value) throw;            // Check if the sender has enough
		if (_value <= 0) throw;
        freezeOf[msg.sender] = SafeMath.safeSubtract(freezeOf[msg.sender], _value);                      // Subtract from the sender
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
	function() public payable {
    }
}