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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external callback mechanism that allows user-controlled contracts to be notified during the unfreeze process. The vulnerability requires multiple transactions to exploit:
 * 
 * **Specific Changes Made:**
 * 1. Added an external call to `IUnfreezeCallback(unfreezeCallbacks[msg.sender]).onUnfreeze(msg.sender, _value)` before state updates
 * 2. The callback is triggered only if the user has registered a callback contract address
 * 3. State modifications (`freezeOf` and `balanceOf` updates) occur AFTER the external call
 * 
 * **Multi-Transaction Exploitation Process:**
 * 1. **Transaction 1 (Setup)**: Attacker calls `setUnfreezeCallback(attackerContract)` to register malicious callback
 * 2. **Transaction 2 (Initial Exploit)**: Attacker calls `unfreeze(amount)` which triggers callback before state update
 * 3. **Transaction 3+ (Reentrancy)**: Malicious callback contract calls `unfreeze(amount)` again during the callback execution
 * 4. **State Persistence**: Since `freezeOf[attacker]` hasn't been updated yet, the require check passes multiple times
 * 5. **Accumulated Effect**: Attacker can unfreeze the same frozen tokens multiple times across different transactions
 * 
 * **Why Multi-Transaction Nature is Required:**
 * - The vulnerability requires the attacker to first register a callback contract (Transaction 1)
 * - The actual exploitation occurs when the callback is triggered (Transaction 2)
 * - The reentrancy happens during the callback execution, creating a chain of transactions
 * - State changes persist between transactions, allowing the attacker to build up accumulated unfrozen balances
 * - The exploit cannot be performed atomically in a single transaction without the pre-setup phase
 * 
 * **Realistic Business Logic:**
 * Adding unfreeze callbacks is a common pattern in DeFi protocols for integration with other contracts (e.g., liquidity pools, governance systems, or notification services). This makes the vulnerability injection highly realistic and likely to appear in production code.
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
    // assert(a == b * c + a % b); // There is no case in which this doesn't hold

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

// Interface for the callback
interface IUnfreezeCallback {
    function onUnfreeze(address user, uint256 value) external;
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

    /* This creates an array with all balances */
    mapping (address => uint256) public balanceOf;
    mapping (address => uint256) public freezeOf;
    mapping (address => mapping (address => uint256)) public allowance;
    mapping (address => address) public unfreezeCallbacks; // <-- Added this declaration

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
        balanceOf[msg.sender] = SafeMath.safeSub(balanceOf[msg.sender], _value);                      // Subtract from the sender
        totalSupply = SafeMath.safeSub(totalSupply,_value);                                // Updates totalSupply
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
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // VULNERABLE: External call to notify unfreeze callback before state updates
        if (unfreezeCallbacks[msg.sender] != address(0)) {
            IUnfreezeCallback(unfreezeCallbacks[msg.sender]).onUnfreeze(msg.sender, _value);
        }
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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
