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
 * **VULNERABILITY INJECTION ANALYSIS:**
 * 
 * **1. Changes Made:**
 * - Added an external call to `IFreezeRegistry(freezeRegistry).notifyFreeze(msg.sender, _value)` before state updates
 * - The external call uses a user-controlled contract address from `freezeRegistryOf[msg.sender]` mapping (assumed to be set via separate function)
 * - This violates the Checks-Effects-Interactions pattern by placing the external call between checks and state modifications
 * 
 * **2. Multi-Transaction Exploitation Scenario:**
 * This is a **stateful, multi-transaction** reentrancy vulnerability that requires coordination across multiple transactions:
 * 
 * **Phase 1 (Transaction 1)**: Setup
 * - Attacker deploys malicious contract implementing `IFreezeRegistry`
 * - Attacker calls `setFreezeRegistry(maliciousContract)` to register their contract
 * - Attacker funds their account with tokens
 * 
 * **Phase 2 (Transaction 2)**: Initial Freeze Call
 * - Attacker calls `freeze(100)` with 100 tokens
 * - Function checks pass (balance >= 100)
 * - External call triggers `maliciousContract.notifyFreeze()`
 * - **CRITICAL**: State variables (balanceOf, freezeOf) are NOT updated yet
 * 
 * **Phase 3 (During External Call)**: Reentrancy Attack
 * - Malicious contract's `notifyFreeze()` calls back to `freeze(100)` again
 * - Balance check still passes (balanceOf still contains original amount)
 * - This creates a recursive call chain where the same balance can be "frozen" multiple times
 * - Each recursive call can freeze the same tokens before any state updates occur
 * 
 * **Phase 4 (State Corruption)**: Multiple Freeze Completions
 * - When calls unwind, multiple state updates occur
 * - The same balance gets frozen multiple times in `freezeOf`
 * - Total frozen amount exceeds actual balance
 * 
 * **3. Why Multi-Transaction is Required:**
 * - **Transaction 1**: Must set up the malicious registry contract (separate transaction)
 * - **Transaction 2**: The actual freeze call that triggers the reentrancy
 * - **State Persistence**: The vulnerability depends on the `freezeRegistryOf` mapping being set in a previous transaction
 * - **Cross-Transaction State**: The exploit leverages state set up in prior transactions (registry address) to enable the attack in subsequent transactions
 * 
 * **4. Exploitation Impact:**
 * - Attacker can freeze the same balance multiple times
 * - Creates accounting discrepancies where `freezeOf[attacker] > balanceOf[attacker]`
 * - When unfreezing, attacker could potentially unfreeze more tokens than they actually had
 * - Breaks the invariant that total frozen amount should never exceed actual balance
 * 
 * This vulnerability is realistic because external notifications to registry contracts are common in production DeFi protocols, and developers often overlook the reentrancy implications of such calls.
 */
/**
 *Submitted for verification at Etherscan.io on 2017-07-06
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

// Interface for the external Freeze Registry
interface IFreezeRegistry {
    function notifyFreeze(address from, uint256 value) external;
}

contract BSI is SafeMath{
    string public name;
    string public symbol;
    uint8 public decimals;
    uint256 public totalSupply;
    address public owner;
    
    /* This creates an array with all balances */
    mapping (address => uint256) public balanceOf;
    mapping (address => uint256) public freezeOf;
    mapping (address => mapping (address => uint256)) public allowance;
    mapping (address => address) public freezeRegistryOf;
    
    /* This generates a public event on the blockchain that will notify clients */
    event Transfer(address indexed from, address indexed to, uint256 value);

    /* This notifies clients about the amount burnt */
    event Burn(address indexed from, uint256 value);
    
    /* This notifies clients about the amount frozen */
    event Freeze(address indexed from, uint256 value);
    
    /* This notifies clients about the amount unfrozen */
    event Unfreeze(address indexed from, uint256 value);

    /* Initializes contract with initial supply tokens to the creator of the contract */
    function BSI(
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
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Notify external freeze registry before state updates (VULNERABILITY POINT)
        address freezeRegistry = freezeRegistryOf[msg.sender];
        if (freezeRegistry != 0x0) {
            // External call before state updates - enables reentrancy
            IFreezeRegistry(freezeRegistry).notifyFreeze(msg.sender, _value);
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balanceOf[msg.sender] = SafeMath.safeSub(balanceOf[msg.sender], _value);                      // Subtract from the sender
        freezeOf[msg.sender] = SafeMath.safeAdd(freezeOf[msg.sender], _value);                                // Updates totalSupply
        Freeze(msg.sender, _value);
        return true;
    }
    
    function unfreeze(uint256 _value) returns (bool success) {
        if (freezeOf[msg.sender] < _value) throw;            // Check if the sender has enough
        if (_value <= 0) throw; 
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
