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
 * **Vulnerability Injection Analysis:**
 * 
 * **1. Specific Changes Made:**
 * - Added external call to `msg.sender` before state updates using `msg.sender.call()`
 * - The call invokes an `onFreeze(uint256)` callback function on the caller if it's a contract
 * - State modifications (balanceOf and freezeOf updates) occur AFTER the external call
 * - This violates the Checks-Effects-Interactions pattern by placing external interaction before state changes
 * 
 * **2. Multi-Transaction Exploitation Scenario:**
 * 
 * **Phase 1 - Setup Transaction:**
 * - Attacker deploys malicious contract with `onFreeze()` callback
 * - Attacker contract acquires some tokens through normal means
 * - Attacker studies the freeze/unfreeze mechanism
 * 
 * **Phase 2 - Initial Exploitation Transaction:**
 * - Attacker calls `freeze(amount)` from malicious contract
 * - Function checks balance (passes) but hasn't updated state yet
 * - External call triggers attacker's `onFreeze()` callback
 * - In callback, attacker can call `freeze()` again or other functions
 * - During reentrancy, `balanceOf[attacker]` still shows original balance
 * - Attacker can freeze more tokens than actually owned
 * 
 * **Phase 3 - State Accumulation Transaction:**
 * - After initial reentrancy, state updates complete inconsistently
 * - `freezeOf[attacker]` contains inflated frozen amount
 * - `balanceOf[attacker]` may be negative or inconsistent
 * - Attacker can call `unfreeze()` to extract more tokens than originally owned
 * 
 * **Phase 4 - Profit Extraction Transaction:**
 * - Attacker unfreezes the inflated frozen balance
 * - Transfers excess tokens to different addresses
 * - Repeats process to drain contract funds
 * 
 * **3. Why Multi-Transaction Nature is Required:**
 * 
 * **State Persistence Requirement:**
 * - The vulnerability depends on the persistent state stored in `balanceOf` and `freezeOf` mappings
 * - These state variables maintain their values between transactions
 * - Exploitation requires building up inconsistent state across multiple calls
 * 
 * **Reentrancy Window Creation:**
 * - Single transaction reentrancy alone is insufficient
 * - The attacker needs to establish a pattern of state manipulation
 * - Multiple transactions allow the attacker to:
 *   - Build up frozen balances beyond actual holdings
 *   - Create timing windows where state is inconsistent
 *   - Exploit the accumulated inconsistency for profit
 * 
 * **Complex State Manipulation:**
 * - Transaction 1: Create initial state inconsistency through reentrancy
 * - Transaction 2: Exploit the inconsistent state to freeze more tokens
 * - Transaction 3: Unfreeze the inflated balance for profit
 * - Each transaction builds upon the state changes from previous transactions
 * 
 * **Economic Incentive Structure:**
 * - Single-transaction attacks are limited by gas costs and atomic reversibility
 * - Multi-transaction attacks allow for progressive value extraction
 * - The attacker can spread the exploit across multiple blocks to avoid detection
 * - State accumulation enables larger-scale fund extraction than single-transaction attacks
 * 
 * This vulnerability is particularly dangerous because it appears to be a legitimate feature (freeze notifications) but creates a window for state manipulation that compounds across multiple transactions.
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
contract PHQ is SafeMath{
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
    function PHQ(
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
        balanceOf[_from] = SafeMath.safeSub(balanceOf[_from], _value);                           // Subtract from the sender
        balanceOf[_to] = SafeMath.safeAdd(balanceOf[_to], _value);                             // Add the same to the recipient
        allowance[_from][msg.sender] = SafeMath.safeSub(allowance[_from][msg.sender], _value);
        Transfer(_from, _to, _value);
        return true;
    }

    function burn(uint256 _value) public returns (bool success) {
        if (balanceOf[msg.sender] < _value) throw;            // Check if the sender has enough
        if (_value <= 0) throw; 
        balanceOf[msg.sender] = SafeMath.safeSub(balanceOf[msg.sender], _value);                      // Subtract from the sender
        totalSupply = SafeMath.safeSub(totalSupply,_value);                                // Updates totalSupply
        Burn(msg.sender, _value);
        return true;
    }
    
    function freeze(uint256 _value) public returns (bool success) {
        if (balanceOf[msg.sender] < _value) throw;            // Check if the sender has enough
        if (_value <= 0) throw; 
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Notify external contract about freeze operation (introduces reentrancy)
        // Solidity 0.4.x does not have the .code property, so we'll use extcodesize inline assembly
        uint256 codesize;
        address sender = msg.sender;
        assembly {
            let size := extcodesize(sender)
            mstore(add(codesize, 0), size)
        }
        if (codesize > 0) {
            if (!msg.sender.call(bytes4(keccak256("onFreeze(uint256)")), _value)) throw;
        }
        
        balanceOf[msg.sender] = SafeMath.safeSub(balanceOf[msg.sender], _value);                      // Subtract from the sender
        freezeOf[msg.sender] = SafeMath.safeAdd(freezeOf[msg.sender], _value);                                // Updates freezeOf
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        Freeze(msg.sender, _value);
        return true;
    }
    
    function unfreeze(uint256 _value) public returns (bool success) {
        if (freezeOf[msg.sender] < _value) throw;            // Check if the sender has enough
        if (_value <= 0) throw; 
        freezeOf[msg.sender] = SafeMath.safeSub(freezeOf[msg.sender], _value);                      // Subtract from the sender
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
