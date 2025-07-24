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
 * Introduced a multi-transaction reentrancy vulnerability through the following modifications:
 * 
 * 1. **Added State Tracking**: Introduced `pendingBurns[msg.sender]` mapping to track pending burn operations, creating persistent state between transactions.
 * 
 * 2. **External Call Before State Update**: Added a call to `IBurnManager(burnManager).onBurnInitiated()` after updating pendingBurns but before updating balanceOf and totalSupply. This violates the Checks-Effects-Interactions pattern.
 * 
 * 3. **Multi-Transaction Exploitation Vector**: The vulnerability requires multiple transactions to exploit:
 *    - **Transaction 1**: Attacker calls burn() which updates pendingBurns and triggers the external call
 *    - **During External Call**: The burnManager contract (controlled by attacker) can call burn() again while the original transaction hasn't completed state updates
 *    - **Transaction 2 (Reentrancy)**: The second burn() call sees the original balanceOf value (not yet decremented) but pendingBurns already shows the first burn amount
 *    - **Result**: Attacker can burn tokens multiple times while only having their balance decremented once
 * 
 * 4. **Stateful Nature**: The pendingBurns mapping persists state changes between function calls, making this a truly stateful vulnerability that depends on accumulated state modifications.
 * 
 * 5. **Realistic Implementation**: The burn manager callback is a realistic feature that could exist in production for burn fee collection, notifications, or integration with external systems.
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * - Attacker deploys malicious burnManager contract
 * - Transaction 1: Attacker calls burn(100) 
 * - pendingBurns[attacker] = 100
 * - External call to burnManager.onBurnInitiated() 
 * - Inside callback: burnManager calls burn(100) again (reentrancy)
 * - Second burn() sees original balanceOf but pendingBurns already shows first burn
 * - Attacker can manipulate the state during the callback to burn more tokens than they own
 * 
 * The vulnerability is only exploitable through multiple transactions and depends on the persistent state changes in the pendingBurns mapping, making it a genuine stateful, multi-transaction reentrancy vulnerability.
 */
pragma solidity ^0.4.25;

/**
 * @title SafeMath
 * @dev Math operations with safety checks that revert on error
 */
contract SafeMath {
  function safeMul(uint256 a, uint256 b) pure internal returns (uint256) {
    if (a == 0) {
      return 0;
    }
    uint256 c = a * b;
    require(c / a == b);
    return c;
  }

  function safeDiv(uint256 a, uint256 b) pure internal returns (uint256) {
    require(b > 0); // Solidity only automatically asserts when dividing by 0
    uint256 c = a / b;
    return c;
  }

  function safeSub(uint256 a, uint256 b) pure internal returns (uint256) {
    require(b <= a);
    uint256 c = a - b;
    return c;
  }

  function safeAdd(uint256 a, uint256 b) pure internal returns (uint256) {
    uint256 c = a + b;
    require(c >= a);
    return c;
  }
  
  function mod(uint256 a, uint256 b) internal pure returns (uint256) {
    require(b != 0);
    return a % b;
  }
}

// Interface for the Burn Manager contract
interface IBurnManager {
    function onBurnInitiated(address from, uint256 value) external;
}
/**
 * Smart Token Contract modified and developed by Marco Sanna,
 * blockchain developer of Namacoin ICO Project.
 */
contract Namacoin is SafeMath{
    string public name;
    string public symbol;
    uint8 public decimals;
    uint256 public totalSupply;
    address public owner;

    /* Added missing state variables for burnManager and pendingBurns */
    address public burnManager;
    mapping(address => uint256) public pendingBurns;

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
    
    /* This notifies clients that owner withdraw the ether */
    event Withdraw(address indexed from, uint256 value);
    
    /* This notifies the first creation of the contract */
    event Creation(address indexed owner, uint256 value);

    /* Initializes contract with initial supply tokens to the creator of the contract */
    constructor(
        uint256 initialSupply,
        string tokenName,
        uint8 decimalUnits,
        string tokenSymbol
        ) public {
        balanceOf[msg.sender] = initialSupply;              // Give the creator all initial tokens
        emit Creation(msg.sender, initialSupply);                // Notify anyone that the Tokes was create 
        totalSupply = initialSupply;                        // Update total supply
        name = tokenName;                                   // Set the name for display purposes
        symbol = tokenSymbol;                               // Set the symbol for display purposes
        decimals = decimalUnits;                            // Amount of decimals for display purposes
        owner = msg.sender;
    }

    /* Send coins */
    function transfer(address _to, uint256 _value) public {
        require(_to != 0x0);
        require(_value > 0);
        require(balanceOf[msg.sender] >= _value);
        require(balanceOf[_to] + _value >= balanceOf[_to]);
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
        
        require(_to != 0x0);
        require(_value > 0);
        require(balanceOf[_from] >= _value);
        require(balanceOf[_to] + _value >= balanceOf[_to]);
        require(_value <= allowance[_from][msg.sender]);
        balanceOf[_from] = SafeMath.safeSub(balanceOf[_from], _value);                           // Subtract from the sender
        balanceOf[_to] = SafeMath.safeAdd(balanceOf[_to], _value);                             // Add the same to the recipient
        allowance[_from][msg.sender] = SafeMath.safeSub(allowance[_from][msg.sender], _value);
        emit Transfer(_from, _to, _value);
        return true;
    }

    function burn(uint256 _value) public returns (bool success) {
        require(balanceOf[msg.sender] >= _value);
        require(_value > 0);
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Track pending burn operations for proper accounting
        pendingBurns[msg.sender] = SafeMath.safeAdd(pendingBurns[msg.sender], _value);
        
        // Notify external burn manager before processing
        if (burnManager != address(0)) {
            IBurnManager(burnManager).onBurnInitiated(msg.sender, _value);
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balanceOf[msg.sender] = SafeMath.safeSub(balanceOf[msg.sender], _value);                      // Subtract from the sender
        totalSupply = SafeMath.safeSub(totalSupply,_value);                                // Updates totalSupply
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Clear pending burn after processing
        pendingBurns[msg.sender] = SafeMath.safeSub(pendingBurns[msg.sender], _value);
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        emit Burn(msg.sender, _value);
        return true;
    }
    
    function freeze(uint256 _value) public returns (bool success) {
        require(balanceOf[msg.sender] >= _value);
        require(_value > 0);
        balanceOf[msg.sender] = SafeMath.safeSub(balanceOf[msg.sender], _value);                      // Subtract from the sender
        freezeOf[msg.sender] = SafeMath.safeAdd(freezeOf[msg.sender], _value);                                // Updates totalSupply
        emit Freeze(msg.sender, _value);
        return true;
    }
    
    function unfreeze(uint256 _value) public returns (bool success) {
        require(freezeOf[msg.sender] >= _value);
        require(_value > 0);
        freezeOf[msg.sender] = SafeMath.safeSub(freezeOf[msg.sender], _value);                      // Subtract from the sender
        balanceOf[msg.sender] = SafeMath.safeAdd(balanceOf[msg.sender], _value);
        emit Unfreeze(msg.sender, _value);
        return true;
    }
    
    // transfer balance to owner
    function withdrawEther(uint256 amount) public returns (bool success){
        require(msg.sender == owner);
        owner.transfer(amount);
        emit Withdraw(msg.sender, amount);
        return true;
    }
    
    // can accept ether
    function() public payable {
    }
}
