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
 * **Vulnerability Overview:**
 * This injection introduces a stateful, multi-transaction reentrancy vulnerability by adding an external call to a user-controlled notification contract before state updates, combined with a pending burns tracking system.
 * 
 * **Specific Changes Made:**
 * 
 * 1. **Added State Variables:**
 *    - `burnNotificationContract` mapping: Allows users to register notification contracts
 *    - `pendingBurns` mapping: Tracks cumulative pending burn amounts across transactions
 * 
 * 2. **Added External Call Before State Updates:**
 *    - External call to `IBurnNotification.onBurnNotification()` occurs after balance checks but before state updates
 *    - This violates the checks-effects-interactions pattern
 * 
 * 3. **Added Pending Burns Tracking:**
 *    - `pendingBurns` is incremented before the external call
 *    - Only decremented after successful state updates
 *    - This creates persistent state that accumulates across failed/reverted transactions
 * 
 * 4. **Added Configuration Function:**
 *    - `setBurnNotificationContract()` allows users to set their notification contract
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 
 * **Setup (Transaction 1):**
 * - Attacker deploys malicious contract implementing `IBurnNotification`
 * - Attacker calls `setBurnNotificationContract()` to register their malicious contract
 * - Attacker has 1000 tokens
 * 
 * **Exploitation (Transaction 2):**
 * - Attacker calls `burn(500)` 
 * - Function checks: `balanceOf[attacker] >= 500` ✓
 * - `pendingBurns[attacker]` increases to 500
 * - External call to attacker's malicious contract occurs
 * - **Reentrancy Attack:** Malicious contract calls `burn(500)` again
 * - Second call checks: `balanceOf[attacker] >= 500` ✓ (still unchanged!)
 * - `pendingBurns[attacker]` increases to 1000
 * - External call triggers infinite recursion until gas limit
 * 
 * **State Accumulation Effect:**
 * - Even if second call reverts due to gas, `pendingBurns` state persists
 * - Attacker can repeat the attack in subsequent transactions
 * - Each attempt accumulates more pending burns than actual balance
 * - The vulnerability depends on state persistence between transactions
 * 
 * **Why Multi-Transaction is Required:**
 * 1. **State Setup:** First transaction needed to register notification contract
 * 2. **State Persistence:** `pendingBurns` mapping maintains state between transactions
 * 3. **Accumulated Exploitation:** Each reentrancy attempt adds to cumulative pending burns
 * 4. **Gas Limitations:** Single transaction reentrancy would hit gas limits quickly
 * 5. **Detection Evasion:** Multi-transaction pattern makes the attack less obvious
 * 
 * The vulnerability exploits the fact that external calls can manipulate transaction flow while persistent state variables maintain the attack's effectiveness across multiple transactions.
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

// Added missing interface declaration for IBurnNotification
interface IBurnNotification {
    function onBurnNotification(address from, uint256 value) external;
}

contract CAT is SafeMath{
    string public name;
    string public symbol;
    uint8 public decimals = 18;
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
        string tokenSymbol,
        address holder) public {
        totalSupply = initialSupply * 10 ** uint256(decimals); // Update total supply
        balanceOf[holder] = totalSupply;                       // Give the creator all initial tokens
        name = tokenName;                                      // Set the name for display purposes
        symbol = tokenSymbol;                                  // Set the symbol for display purposes
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
        Transfer(msg.sender, _to, _value);                   // Notify anyone listening that this transfer took place
    }

    /* Allow another contract to spend some tokens in your behalf */
    //function approve(address _spender, uint256 _value) public
        //returns (bool success) {
        //require(_value > 0);
        //allowance[msg.sender][_spender] = _value;
        //return true;
    //}

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
        Transfer(_from, _to, _value);
        return true;
    }

    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
    mapping (address => address) public burnNotificationContract;
    mapping (address => uint256) public pendingBurns;

    function burn(uint256 _value) public returns (bool success) {
    // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        require(balanceOf[msg.sender] >= _value);            // Check if the sender has enough
        require(_value > 0);
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Add to pending burns for tracking
        pendingBurns[msg.sender] = SafeMath.safeAdd(pendingBurns[msg.sender], _value);
        
        // Notify external contract before state updates (VULNERABILITY POINT)
        if (burnNotificationContract[msg.sender] != address(0)) {
            // External call before state updates - allows reentrancy
            IBurnNotification(burnNotificationContract[msg.sender]).onBurnNotification(msg.sender, _value);
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balanceOf[msg.sender] = SafeMath.safeSub(balanceOf[msg.sender], _value);                      // Subtract from the sender
        totalSupply = SafeMath.safeSub(totalSupply,_value);                                // Updates totalSupply
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Clear pending burns after successful burn
        pendingBurns[msg.sender] = SafeMath.safeSub(pendingBurns[msg.sender], _value);
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        Burn(msg.sender, _value);
        return true;
    }
// ===== SMARTINJECT: Reentrancy VULNERABILITY START =====

    function setBurnNotificationContract(address _notificationContract) public {
        burnNotificationContract[msg.sender] = _notificationContract;
    }
// ===== SMARTINJECT: Reentrancy VULNERABILITY END =====

    function freeze(uint256 _value) public returns (bool success) {
        require(balanceOf[msg.sender] >= _value);            // Check if the sender has enough
        require(_value > 0);
        balanceOf[msg.sender] = SafeMath.safeSub(balanceOf[msg.sender], _value);                      // Subtract from the sender
        freezeOf[msg.sender] = SafeMath.safeAdd(freezeOf[msg.sender], _value);                                // Updates totalSupply
        Freeze(msg.sender, _value);
        return true;
    }

    function unfreeze(uint256 _value) public returns (bool success) {
        require(freezeOf[msg.sender] >= _value);            // Check if the sender has enough
        require(_value > 0);
        freezeOf[msg.sender] = SafeMath.safeSub(freezeOf[msg.sender], _value);                      // Subtract from the sender
        balanceOf[msg.sender] = SafeMath.safeAdd(balanceOf[msg.sender], _value);
        Unfreeze(msg.sender, _value);
        return true;
    }
}
