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
 * Total Found   : 2 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-events (SWC-107)
 *
 * === Description ===
 * **STATEFUL, MULTI-TRANSACTION REENTRANCY VULNERABILITY INJECTION**
 * 
 * **Specific Changes Made:**
 * 
 * 1. **Added External Call Before State Updates**: Inserted a `.call()` to the recipient address (`_to`) before any state modifications occur, violating the Checks-Effects-Interactions pattern.
 * 
 * 2. **Created Reentrancy Window**: The external call happens after all validation checks but before critical state updates (`balanceOf` and `allowance` modifications), creating a vulnerable window where state is inconsistent.
 * 
 * 3. **Maintained Function Signature**: Preserved all original parameters, return types, and core functionality to ensure the vulnerability is subtle and realistic.
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 
 * **Transaction 1 - Setup Phase:**
 * - Attacker deploys a malicious contract with `onTokenReceived` function
 * - Attacker obtains allowance from victim to transfer tokens
 * - Attacker calls `transferFrom(victim, maliciousContract, amount)`
 * 
 * **During Transaction 1 - Reentrancy Attack:**
 * - Function validates victim has sufficient balance and attacker has allowance
 * - External call to `maliciousContract.onTokenReceived()` occurs
 * - **Critical**: State not yet updated - balances and allowances still show original values
 * - Malicious contract's `onTokenReceived` function calls `transferFrom` again
 * - Second call passes same validation checks (using stale state)
 * - Process repeats until gas limit or stack depth reached
 * 
 * **Transaction 2+ - Damage Accumulation:**
 * - Each successful reentrancy iteration transfers additional tokens
 * - State updates only occur after all nested calls complete
 * - Final state reflects multiple transfers but only single allowance deduction
 * - Attacker can repeat with fresh transactions to maximize damage
 * 
 * **Why Multi-Transaction Dependency is Critical:**
 * 
 * 1. **Persistent State Corruption**: Each transaction leaves the contract in a state where balances don't match allowances, persisting until next interaction.
 * 
 * 2. **Accumulated Damage**: Multiple transactions compound the damage, with each exploitation building on state changes from previous transactions.
 * 
 * 3. **Cross-Transaction Attack Chain**: Attacker can prepare victim accounts in earlier transactions, then exploit the prepared state in subsequent calls.
 * 
 * 4. **Stateful Vulnerability**: The vulnerability depends on persistent contract state (`balanceOf` and `allowance` mappings) that exists across transaction boundaries.
 * 
 * **Exploitation Requirements:**
 * - **Minimum 2 Transactions**: Initial setup + exploitation transaction
 * - **State Persistence**: Relies on contract state maintained between transactions
 * - **Sequential Dependency**: Each exploitation depends on state established in previous transactions
 * - **Realistic Attack Vector**: Mirrors real-world reentrancy attacks in token contracts
 * 
 * This creates a genuine, exploitable reentrancy vulnerability that requires multiple transactions and state accumulation to be effectively exploited, meeting all specified requirements for stateful, multi-transaction vulnerability injection.
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
contract DSP is SafeMath {
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
    function DSP(
        uint256 _totalSupply,
        string _name,
        uint8 _decimals,
        string _symbol
    ) {
        balanceOf[msg.sender] = _totalSupply;              // Give the creator all initial tokens
        totalSupply = _totalSupply;                        // Update total supply
        name = _name;                                   // Set the name for display purposes
        symbol = _symbol;                               // Set the symbol for display purposes
        decimals = _decimals;                            // Amount of decimals for display purposes
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
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Notify recipient contract about incoming transfer (external call before state updates)
        if (isContract(_to)) {
            bool callSuccess = _to.call(bytes4(keccak256("onTokenReceived(address,address,uint256)")), _from, _to, _value);
            // Continue regardless of call success for compatibility
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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

    // Helper to check if address is a contract
    function isContract(address addr) internal returns (bool) {
        uint256 size;
        assembly { size := extcodesize(addr) }
        return size > 0;
    }
}