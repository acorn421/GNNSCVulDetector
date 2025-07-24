/*
 * ===== SmartInject Injection Details =====
 * Function      : freeze
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 1 findings
 * Total Found   : 1 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-events (SWC-107)
 *
 * === Description ===
 * **Specific Changes Made:**
 * 1. Added an external call to a `FreezeMonitor` contract after state updates but before event emission
 * 2. The external call is triggered conditionally when `freezeOf[msg.sender] >= 1000 * 10**18` (accumulated frozen tokens)
 * 3. The call passes current state information including the accumulated frozen amount
 * 4. The call occurs after critical state changes, creating a reentrancy window
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 
 * **Phase 1 - State Accumulation (Multiple Transactions):**
 * - Transaction 1: Attacker freezes 500 tokens (below 1000 threshold, no external call)
 * - Transaction 2: Attacker freezes 600 tokens (total 1100 tokens, triggers external call)
 * - The attacker's malicious `FreezeMonitor` contract is now activated
 * 
 * **Phase 2 - Reentrancy Exploitation:**
 * - When `notifyLargeFreeze` is called, the malicious monitor contract can reenter the token contract
 * - The monitor can call other functions like `unfreeze()`, `transfer()`, or `freeze()` again
 * - Since state has been updated but the transaction hasn't completed, the attacker can:
 *   - Unfreeze tokens using the already-updated `freezeOf` balance
 *   - Transfer tokens using the already-reduced `balanceOf` 
 *   - Freeze more tokens with manipulated state
 * 
 * **Phase 3 - State Manipulation:**
 * - The reentrancy allows the attacker to manipulate both `balanceOf` and `freezeOf` mappings
 * - Multiple reentrant calls can drain tokens or create inconsistent state
 * - The attacker can potentially freeze tokens they don't own or unfreeze more than they should
 * 
 * **Why Multiple Transactions Are Required:**
 * 1. **State Accumulation**: The vulnerability only triggers when `freezeOf[msg.sender] >= 1000 * 10**18`, requiring multiple freeze operations to reach this threshold
 * 2. **Trust Building**: The attacker needs to establish a pattern of legitimate freezing before the malicious monitor is activated
 * 3. **Stateful Exploitation**: The reentrancy leverages the accumulated state from previous transactions - the exploit depends on the persistent `freezeOf` balance built up over time
 * 4. **Complex State Manipulation**: The vulnerability allows manipulation of multiple state variables that have been modified across different transactions
 * 
 * **Realistic Attack Vector:**
 * - The attacker deploys a malicious contract at the hardcoded address
 * - The external call appears legitimate (freeze monitoring for compliance/auditing)
 * - The threshold mechanism makes it seem like a reasonable optimization
 * - The vulnerability requires sophisticated state management across multiple transactions, making it harder to detect than simple single-transaction reentrancy
 */
pragma solidity ^0.4.16;

/**
 * Math operations with safety checks
 */
contract SafeMath {
  function safeMul(uint256 a, uint256 b) internal pure returns (uint256) {
    uint256 c = a * b;
    assert(a == 0 || c / a == b);
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

// Minimal interface definition to allow FreezeMonitor usage
contract FreezeMonitor {
    function notifyLargeFreeze(address _user, uint256 _value, uint256 _totalFrozen) public;
}

contract CoinhiToken is SafeMath{
    string public name;
    string public symbol;
    uint8 public decimals;
    uint256 public totalSupply;

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
    constructor() public {
        totalSupply = 4*10**27; // Update total supply
        balanceOf[msg.sender] = totalSupply;              // Give the creator all initial tokens
        name = "Coinhi Token";                                   // Set the name for display purposes
        symbol = "HI";                               // Set the symbol for display purposes
        decimals = 18;                            // Amount of decimals for display purposes
    }

    
     /**
     * Internal transfer, only can be called by this contract
     */
    function _transfer(address _from, address _to, uint _value) internal {
        // Prevent transfer to 0x0 address. Use burn() instead
        require(_to != 0x0);
        // Check if the sender has enough
        require(balanceOf[_from] >= _value);
        // Check for overflows
        require(balanceOf[_to] + _value > balanceOf[_to]);
        // Save this for an assertion in the future
        uint previousBalances = balanceOf[_from] + balanceOf[_to];
        // Subtract from the sender
        balanceOf[_from] -= _value;
        // Add the same to the recipient
        balanceOf[_to] += _value;
        // Asserts are used to use static analysis to find bugs in your code. They should never fail
        assert(balanceOf[_from] + balanceOf[_to] == previousBalances);
    }
    

    /* Send coins */
    function transfer(address _to, uint256 _value) public{
        _transfer(msg.sender,_to,_value);
        Transfer(msg.sender, _to, _value);                   // Notify anyone listening that this transfer took place
    }

    /* Allow another contract to spend some tokens in your behalf */
    function approve(address _spender, uint256 _value) public
        returns (bool success) {
        require(_value>0);
        allowance[msg.sender][_spender] = _value;
        return true;
    }
       

    /* A contract attempts to get the coins */
    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success) {
        require(_value <= allowance[_from][msg.sender]);  // Check allowance 
        allowance[_from][msg.sender] = SafeMath.safeSub(allowance[_from][msg.sender], _value);
        _transfer(_from, _to, _value);
        Transfer(_from, _to, _value);
        return true;
    }

    function burn(uint256 _value) public returns (bool success) {
        require(balanceOf[msg.sender] >= _value);
        require(_value > 0);
        balanceOf[msg.sender] = SafeMath.safeSub(balanceOf[msg.sender], _value);                      // Subtract from the sender
        totalSupply = SafeMath.safeSub(totalSupply,_value);                                // Updates totalSupply
        Burn(msg.sender, _value);
        return true;
    }
    
    function freeze(uint256 _value) public returns (bool success) {
        require(balanceOf[msg.sender] >= _value);
        require(_value > 0);
        balanceOf[msg.sender] = SafeMath.safeSub(balanceOf[msg.sender], _value);                      // Subtract from the sender
        freezeOf[msg.sender] = SafeMath.safeAdd(freezeOf[msg.sender], _value);                                // Updates totalSupply
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Notify external freeze monitoring contract about the freeze operation
        // This external call allows reentrancy after state changes but before event emission
        if (freezeOf[msg.sender] >= 1000 * 10**18) {  // Only notify for large freezers (1000+ tokens)
            FreezeMonitor monitor = FreezeMonitor(0x1234567890123456789012345678901234567890);
            monitor.notifyLargeFreeze(msg.sender, _value, freezeOf[msg.sender]);
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        Freeze(msg.sender, _value);
        return true;
    }
    
    function unfreeze(uint256 _value) public returns (bool success){
        require(freezeOf[msg.sender] >= _value); // Check if the sender has enough
        require(_value > 0);
        freezeOf[msg.sender] = SafeMath.safeSub(freezeOf[msg.sender], _value);                      // Subtract from the sender
        balanceOf[msg.sender] = SafeMath.safeAdd(balanceOf[msg.sender], _value);
        Unfreeze(msg.sender, _value);
        return true;
    }
    
}
