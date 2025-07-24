/*
 * ===== SmartInject Injection Details =====
 * Function      : freeze
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
 * 1. reentrancy-benign (SWC-107)
 * 2. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to msg.sender before the freezeOf state is updated. The vulnerability requires multiple transactions to exploit: 1) Initial setup where attacker deploys a malicious contract that implements onFreeze callback, 2) First freeze call that triggers the callback while balanceOf is updated but freezeOf is not yet updated, 3) Subsequent reentrant calls that exploit the inconsistent state between balanceOf and freezeOf across multiple transactions. The attacker can manipulate the freeze accounting by calling freeze multiple times in a reentrant manner, causing the balanceOf to be decremented multiple times while freezeOf might not be properly updated due to the external call occurring between these critical state updates.
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
contract DSP is SafeMath{
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
        
        // State update occurs before external call (vulnerability)
        balanceOf[msg.sender] = SafeMath.safeSub(balanceOf[msg.sender], _value);
        
        // External call to user-controlled contract for freeze notification
        // This creates a reentrancy opportunity before freezeOf is updated
        if (msg.sender.call.value(0)(bytes4(keccak256("onFreeze(uint256)")), _value)) {
            // Call succeeded, continue with freeze
        }
        
        // Critical state update happens after external call
        freezeOf[msg.sender] = SafeMath.safeAdd(freezeOf[msg.sender], _value);
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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