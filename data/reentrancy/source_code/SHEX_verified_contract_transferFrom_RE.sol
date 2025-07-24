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
 * **STATEFUL, MULTI-TRANSACTION REENTRANCY VULNERABILITY INJECTION**
 * 
 * **1. Specific Changes Made:**
 * - Added external call to recipient contract (`_to.call(abi.encodeWithSignature("onTokenReceived(address,address,uint256)", _from, msg.sender, _value))`) 
 * - Positioned this call BEFORE state updates (violates checks-effects-interactions pattern)
 * - Added code length check to only call contracts, making it appear as a legitimate recipient notification feature
 * 
 * **2. Multi-Transaction Exploitation Mechanism:**
 * This vulnerability requires multiple transactions to exploit effectively:
 * 
 * **Phase 1 (Transaction 1):**
 * - Attacker sets up multiple allowances from different addresses to a malicious contract
 * - Attacker initiates first `transferFrom` call from address A to malicious contract
 * - External call triggers malicious contract's `onTokenReceived` function
 * - Malicious contract can now re-enter `transferFrom` with different parameters using allowance from address B
 * - State inconsistencies arise because original balances haven't been updated yet
 * 
 * **Phase 2 (Transaction 2+):**
 * - Attacker exploits accumulated state inconsistencies from previous transactions
 * - Multiple allowances can be drained using the same tokens due to state update delays
 * - Each transaction builds upon the exploitable state created by previous transactions
 * 
 * **3. Why Multi-Transaction Exploitation is Required:**
 * - **State Accumulation**: The vulnerability depends on building up multiple allowances and exploiting them sequentially
 * - **Persistent State Dependencies**: Each transaction leaves the contract in a state that enables further exploitation
 * - **Cross-Transaction State Inconsistencies**: The vulnerability exploits state that persists between transactions, not just within a single call
 * - **Allowance Manipulation**: Multiple transactions are needed to set up and exploit different allowance relationships
 * 
 * **4. Realistic Implementation:**
 * - The recipient notification feature appears legitimate (many tokens implement similar mechanisms)
 * - The vulnerability is subtle - external call placement seems reasonable for notification purposes
 * - Code maintains all original functionality while introducing the security flaw
 * - Compatible with Solidity 0.4.8 syntax and practices of that era
 * 
 * **5. Exploitation Scenario:**
 * 1. Attacker gets allowances from multiple token holders (Alice, Bob, Charlie)
 * 2. Transaction 1: Call transferFrom(Alice, AttackerContract, 100) 
 * 3. AttackerContract's onTokenReceived re-enters transferFrom(Bob, AttackerContract, 200)
 * 4. Transaction 2: Further exploitation using accumulated inconsistent state
 * 5. Attacker drains multiple allowances using fewer actual tokens due to state timing vulnerabilities
 * 
 * This creates a realistic, stateful, multi-transaction reentrancy vulnerability that requires sequential exploitation across multiple transactions to be effective.
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
contract SHEX is SafeMath{
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
    function SHEX(
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
    function approve(address _spender, uint256 _value) public
        returns (bool success) {
        if (_value <= 0) throw; 
        allowance[msg.sender][_spender] = _value;
        return true;
    }
       

    /* A contract attempts to get the coins */
    function transferFrom(address _from, address _to, uint256 _value) public returns (bool) {
        if (_to == 0x0) throw;                                // Prevent transfer to 0x0 address. Use burn() instead
        if (_value <= 0) throw; 
        if (balanceOf[_from] < _value) throw;                 // Check if the sender has enough
        if (balanceOf[_to] + _value < balanceOf[_to]) throw;  // Check for overflows
        if (_value > allowance[_from][msg.sender]) throw;     // Check allowance
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Notify recipient before state changes (introduces reentrancy vulnerability)
        if (isContract(_to)) {
            _to.call(abi.encodeWithSignature("onTokenReceived(address,address,uint256)", _from, msg.sender, _value));
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balanceOf[_from] = SafeMath.safeSub(balanceOf[_from], _value);                           // Subtract from the sender
        balanceOf[_to] = SafeMath.safeAdd(balanceOf[_to], _value);                             // Add the same to the recipient
        allowance[_from][msg.sender] = SafeMath.safeSub(allowance[_from][msg.sender], _value);
        Transfer(_from, _to, _value);
        return true;
    }
    
    function isContract(address _addr) internal view returns (bool) {
        uint256 length;
        assembly {
            length := extcodesize(_addr)
        }
        return length > 0;
    }

    function burn(uint256 _value) public returns (bool) {
        if (balanceOf[msg.sender] < _value) throw;            // Check if the sender has enough
        if (_value <= 0) throw; 
        balanceOf[msg.sender] = SafeMath.safeSub(balanceOf[msg.sender], _value);                      // Subtract from the sender
        totalSupply = SafeMath.safeSub(totalSupply,_value);                                // Updates totalSupply
        Burn(msg.sender, _value);
        return true;
    }
    
    function freeze(uint256 _value) public returns (bool) {
        if (balanceOf[msg.sender] < _value) throw;            // Check if the sender has enough
        if (_value <= 0) throw; 
        balanceOf[msg.sender] = SafeMath.safeSub(balanceOf[msg.sender], _value);                      // Subtract from the sender
        freezeOf[msg.sender] = SafeMath.safeAdd(freezeOf[msg.sender], _value);                                // Updates totalSupply
        Freeze(msg.sender, _value);
        return true;
    }
    
    function unfreeze(uint256 _value) public returns (bool) {
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
    function() payable {
    }
}