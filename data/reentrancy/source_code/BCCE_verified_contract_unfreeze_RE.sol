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
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-benign (SWC-107)
 * 3. reentrancy-events (SWC-107)
 *
 * === Description ===
 * **SPECIFIC CHANGES MADE:**
 * 
 * 1. **Added External Call Before State Updates**: Introduced a call to `IRewardContract(rewardContract).notifyUnfreeze()` that executes BEFORE the critical state variables (`freezeOf` and `balanceOf`) are updated.
 * 
 * 2. **Violation of Checks-Effects-Interactions Pattern**: The external call now happens after checks but before effects, creating a reentrancy window where the contract state is inconsistent.
 * 
 * 3. **Passes Current State to External Contract**: The external call receives the current frozen balance (`freezeOf[msg.sender]`) before it's reduced, allowing the external contract to see stale state.
 * 
 * **MULTI-TRANSACTION EXPLOITATION SCENARIO:**
 * 
 * **Transaction 1 - Initial Setup:**
 * - Attacker deploys malicious contract that implements `IRewardContract`
 * - Attacker calls `freeze()` to lock tokens (e.g., 1000 tokens)
 * - Contract admin sets `rewardContract` to attacker's malicious contract
 * 
 * **Transaction 2 - First Unfreeze (Exploitation Begins):**
 * - Attacker calls `unfreeze(500)` 
 * - Function passes checks (has 1000 frozen tokens)
 * - External call to malicious contract occurs with current state (1000 frozen)
 * - Malicious contract can now see that user has 1000 frozen tokens but state hasn't been updated yet
 * 
 * **Transaction 3 - Reentrant Call (Exploitation Continues):**
 * - During the external call callback, malicious contract calls `unfreeze(500)` again
 * - This second call also passes checks because `freezeOf[msg.sender]` still shows 1000 tokens
 * - This creates a race condition where multiple unfreeze operations are "pending"
 * 
 * **Transaction 4+ - State Accumulation Exploitation:**
 * - Each reentrant call can drain more tokens than actually frozen
 * - The attacker can unfreeze the same tokens multiple times before any state updates occur
 * - Multiple calls accumulate to drain more tokens than were originally frozen
 * 
 * **WHY MULTI-TRANSACTION REQUIRED:**
 * 
 * 1. **State Accumulation**: The vulnerability requires building up frozen token balances over multiple transactions before exploitation
 * 2. **Reentrancy Chain**: Each reentrant call depends on the state left by previous calls
 * 3. **External Contract Dependency**: The malicious contract needs to be deployed and registered first
 * 4. **Sequential Exploitation**: The attack requires a sequence of calls where later calls exploit state changes from earlier calls
 * 
 * **REALISTIC INTEGRATION RATIONALE:**
 * 
 * This injection appears as a legitimate DeFi feature where:
 * - External reward contracts are notified when tokens are unfrozen
 * - Integration with staking or farming protocols is common
 * - The callback provides current balance information for reward calculations
 * - Such patterns are frequently seen in production DeFi contracts
 * 
 * The vulnerability is subtle because the external call appears to be a harmless notification, but actually creates a critical reentrancy window that can be exploited across multiple transactions.
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

interface IRewardContract {
    function notifyUnfreeze(address from, uint256 value, uint256 previousFreeze) external;
}

contract BCCE is SafeMath{
    string public name;
    string public symbol;
    uint8 public decimals;
    uint256 public totalSupply;
    address public owner;
    address public rewardContract;

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
    function BCCE(
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
        // INJECTED: External callback to notify reward contract before state updates
        // This creates a reentrancy window where state hasn't been updated yet
        if (rewardContract != address(0)) {
            // Call external contract with current frozen balance (before reduction)
            IRewardContract(rewardContract).notifyUnfreeze(msg.sender, _value, freezeOf[msg.sender]);
        }
        // State updates happen AFTER external call - vulnerable to reentrancy
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
