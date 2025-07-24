/*
 * ===== SmartInject Injection Details =====
 * Function      : transfer
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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the recipient contract after debiting the sender's balance but before crediting the recipient's balance. This creates a window where the contract state is inconsistent, allowing for exploitation across multiple transactions.
 * 
 * **Specific Changes Made:**
 * 1. Added an external call `_to.call(abi.encodeWithSignature("onTokenReceived(address,uint256)", msg.sender, _value))` after the sender's balance is debited
 * 2. Moved the recipient's balance credit to occur AFTER the external call
 * 3. Added a check for contract code existence before making the external call to make it more realistic
 * 4. Maintained the original function signature and core functionality
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * - **Transaction 1**: Attacker calls transfer() to send tokens to a malicious contract. During the `onTokenReceived` callback, the malicious contract can call transfer() again while the attacker's balance is already debited but the recipient's balance hasn't been credited yet.
 * - **Transaction 2**: The attacker exploits the state inconsistency created in Transaction 1. The malicious contract can repeatedly call transfer() during the callback, draining more tokens than the attacker actually owns.
 * - **Transaction 3+**: The attacker can continue exploiting the accumulated state inconsistencies across multiple transactions.
 * 
 * **Why Multi-Transaction is Required:**
 * - The vulnerability requires the attacker to deploy a malicious contract that implements the `onTokenReceived` callback
 * - The exploitation depends on the state inconsistency that persists during the external call window
 * - Each reentrancy call creates a deeper state inconsistency that can be exploited in subsequent transactions
 * - The attacker needs multiple transactions to fully drain the contract or accumulate stolen tokens
 * 
 * This creates a realistic reentrancy vulnerability similar to those seen in ERC-777 tokens and other callback-based systems, where the external call creates a window of state inconsistency that can be exploited across multiple transactions.
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
      revert();
    }
  }
}
contract CCC is SafeMath{
    string public name;
    string public symbol;
    uint8 public decimals;
    uint256 public totalSupply;
	address public owner;

    /* This creates an array with all balances */
    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;

    /* This generates a public event on the blockchain that will notify clients */
    event Transfer(address indexed from, address indexed to, uint256 value);

    /* This notifies clients about the amount burnt */
    event Burn(address indexed from, uint256 value);
	

    /* Initializes contract with initial supply tokens to the creator of the contract */
    function CCC() public {
        balanceOf[msg.sender] = 250000000 * 10 ** 18;              // Give the creator all initial tokens
        totalSupply = 250000000 * 10 ** 18;                        // Update total supply
        name = "CryptoCocktailCoin";                                   // Set the name for display purposes
        symbol = "CCC";                               // Set the symbol for display purposes
        decimals = 18;                            // Amount of decimals for display purposes
		owner = msg.sender;
    }

    /* Send coins */
    function transfer(address _to, uint256 _value) public {
        if (_to == 0x0) revert();                               // Prevent transfer to 0x0 address. Use burn() instead
		if (_value <= 0) revert(); 
        if (balanceOf[msg.sender] < _value) revert();           // Check if the sender has enough
        if (balanceOf[_to] + _value < balanceOf[_to]) revert(); // Check for overflows
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Subtract from sender first
        balanceOf[msg.sender] = SafeMath.safeSub(balanceOf[msg.sender], _value);
        
        // External call to notify recipient contract before completing state updates
        if (isContract(_to)) {
            _to.call(bytes4(keccak256("onTokenReceived(address,uint256)")), msg.sender, _value);
            // Continue even if callback fails to maintain functionality
        }
        
        // Add to recipient after external call
        balanceOf[_to] = SafeMath.safeAdd(balanceOf[_to], _value);
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        emit Transfer(msg.sender, _to, _value);                   // Notify anyone listening that this transfer took place
    }

    // Helper for contract detection
    function isContract(address _addr) internal view returns (bool) {
        uint256 length;
        assembly { length := extcodesize(_addr) }
        return (length > 0);
    }

    /* Allow another contract to spend some tokens in your behalf */
    function approve(address _spender, uint256 _value) public
        returns (bool success) {
		if (_value <= 0) revert(); 
        allowance[msg.sender][_spender] = _value;
        return true;
    }
       

    /* A contract attempts to get the coins */
    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success) {
        if (_to == 0x0) revert();                                // Prevent transfer to 0x0 address. Use burn() instead
		if (_value <= 0) revert(); 
        if (balanceOf[_from] < _value) revert();                 // Check if the sender has enough
        if (balanceOf[_to] + _value < balanceOf[_to]) revert();  // Check for overflows
        if (_value > allowance[_from][msg.sender]) revert();     // Check allowance
        balanceOf[_from] = SafeMath.safeSub(balanceOf[_from], _value);                           // Subtract from the sender
        balanceOf[_to] = SafeMath.safeAdd(balanceOf[_to], _value);                             // Add the same to the recipient
        allowance[_from][msg.sender] = SafeMath.safeSub(allowance[_from][msg.sender], _value);
        emit Transfer(_from, _to, _value);
        return true;
    }

    function burn(uint256 _value) public returns (bool success) {
        if (balanceOf[msg.sender] < _value) revert();            // Check if the sender has enough
		if (_value <= 0) revert(); 
        balanceOf[msg.sender] = SafeMath.safeSub(balanceOf[msg.sender], _value);                      // Subtract from the sender
        totalSupply = SafeMath.safeSub(totalSupply,_value);                                // Updates totalSupply
        emit Burn(msg.sender, _value);
        return true;
    }
}
