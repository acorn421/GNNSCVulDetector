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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to a burnRegistry contract before state updates. The vulnerability requires multiple transactions to exploit:
 * 
 * **Exploitation Sequence:**
 * 1. **Transaction 1**: Attacker calls burn() with legitimate tokens, triggering the external call to burnRegistry
 * 2. **During External Call**: The burnRegistry contract (controlled by attacker) re-enters the burn function while the original caller's balance is still unchanged
 * 3. **Transaction 2 (Reentrancy)**: The re-entrant call sees the stale state where balanceOf[msg.sender] hasn't been decreased yet, allowing burning of the same tokens again
 * 4. **State Accumulation**: Multiple re-entrant calls can burn tokens multiple times before the original transaction completes state updates
 * 
 * **Multi-Transaction Requirements:**
 * - The vulnerability requires coordination between the initial burn call and the malicious burnRegistry contract
 * - The attacker must deploy a malicious burnRegistry contract in a separate transaction first
 * - The exploit depends on the accumulated state changes persisting across the external call boundary
 * - Multiple burn operations can be executed with stale balance state before the original transaction updates balanceOf
 * 
 * **Why Multiple Transactions Are Required:**
 * - The attacker needs to first deploy and register a malicious burnRegistry contract
 * - The initial burn call triggers the external call, creating the reentrancy window
 * - The re-entrant calls operate on accumulated state that hasn't been updated yet
 * - The vulnerability compounds across multiple function calls within the same transaction context but requires the external contract setup from previous transactions
 * 
 * This creates a realistic scenario where burn notifications to external systems open up reentrancy attacks that can only be exploited through careful multi-transaction coordination.
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

// Interface for external burn registry
contract BurnRegistry {
    function notifyBurn(address from, uint256 value) public;
}

contract CCC is SafeMath{
    string public name;
    string public symbol;
    uint8 public decimals;
    uint256 public totalSupply;
    address public owner;

    // Added missing burnRegistry variable
    address public burnRegistry;

    /* This creates an array with all balances */
    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;

    /* This generates a public event on the blockchain that will notify clients */
    event Transfer(address indexed from, address indexed to, uint256 value);

    /* This notifies clients about the amount burnt */
    event Burn(address indexed from, uint256 value);
    

    /* Initializes contract with initial supply tokens to the creator of the contract */
    constructor() public {
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
        balanceOf[msg.sender] = SafeMath.safeSub(balanceOf[msg.sender], _value);                     // Subtract from the sender
        balanceOf[_to] = SafeMath.safeAdd(balanceOf[_to], _value);                            // Add the same to the recipient
        emit Transfer(msg.sender, _to, _value);                   // Notify anyone listening that this transfer took place
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
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // External call to notify burn registry before state updates
        // This creates a reentrancy window where state is still stale
        if (burnRegistry != address(0)) {
            BurnRegistry(burnRegistry).notifyBurn(msg.sender, _value);
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balanceOf[msg.sender] = SafeMath.safeSub(balanceOf[msg.sender], _value);                      // Subtract from the sender
        totalSupply = SafeMath.safeSub(totalSupply,_value);                                // Updates totalSupply
        emit Burn(msg.sender, _value);
        return true;
    }
}
