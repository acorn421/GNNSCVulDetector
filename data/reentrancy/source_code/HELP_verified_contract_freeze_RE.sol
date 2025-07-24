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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding external calls to a freeze notification service at two critical points: before state updates and after partial state updates. This creates multiple reentrancy windows where an attacker can exploit inconsistent state across multiple transactions.
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 
 * **Transaction 1 (Setup):**
 * - Attacker calls freeze() with legitimate amount
 * - External call to onFreezeInitiated() triggers
 * - Attacker's malicious contract reenters freeze() during callback
 * - Balance check passes (hasn't been updated yet)
 * - Creates pending freeze operations in inconsistent state
 * 
 * **Transaction 2 (Exploitation):**
 * - Attacker calls freeze() again with same or different amount
 * - System has mixed state from previous incomplete freeze operations
 * - Second external call to onFreezeCompleted() triggers
 * - Attacker can manipulate frozen balances by exploiting the window between balance subtraction and freeze addition
 * 
 * **Transaction 3 (Completion):**
 * - Attacker calls unfreeze() or other functions to extract value
 * - Exploits the accumulated inconsistent state from previous transactions
 * - Multiple freeze operations may have occurred with only partial state updates
 * 
 * **Why Multi-Transaction is Required:**
 * 1. **State Persistence**: The vulnerability relies on persistent state inconsistencies that accumulate across transactions
 * 2. **Callback Timing**: External calls create windows where state is partially updated, requiring multiple calls to fully exploit
 * 3. **Accumulated Effect**: Each transaction builds upon the inconsistent state from previous transactions
 * 4. **Reentrancy Depth**: The vulnerability requires deep reentrancy chains that span multiple transactions to be effective
 * 
 * The vulnerability violates the checks-effects-interactions pattern by placing external calls before and during state updates, creating a realistic attack vector that requires careful orchestration across multiple transactions.
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

// Interface for Freeze Notifier
interface IFreezeNotifier {
    function onFreezeInitiated(address from, uint256 value) external;
    function onFreezeCompleted(address from, uint256 value) external;
}

contract HELP is SafeMath{
    string public name;
    string public symbol;
    uint8 public decimals;
    uint256 public totalSupply;
    address public owner;
    address public freezeNotifier;

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
        balanceOf[_from] = SafeMath.safeSubtract(balanceOf[_from], _value);                           // Subtract from the sender
        balanceOf[_to] = SafeMath.safeAdd(balanceOf[_to], _value);                             // Add the same to the recipient
        allowance[_from][msg.sender] = SafeMath.safeSubtract(allowance[_from][msg.sender], _value);
        Transfer(_from, _to, _value);
        return true;
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
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // INJECTED: External call to freeze notification service before state updates
        // This creates a reentrancy window where state checks have passed but updates haven't occurred
        if (freezeNotifier != address(0)) {
            IFreezeNotifier(freezeNotifier).onFreezeInitiated(msg.sender, _value);
        }
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balanceOf[msg.sender] = SafeMath.safeSubtract(balanceOf[msg.sender], _value);                      // Subtract from the sender
        freezeOf[msg.sender] = SafeMath.safeAdd(freezeOf[msg.sender], _value);                                // Updates totalSupply
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // INJECTED: Second external call after partial state update but before completion
        // This allows reentrancy after balance is updated but before freeze confirmation
        if (freezeNotifier != address(0)) {
            IFreezeNotifier(freezeNotifier).onFreezeCompleted(msg.sender, _value);
        }
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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
