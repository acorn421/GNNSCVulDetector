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
 * This modification introduces a stateful, multi-transaction reentrancy vulnerability by:
 * 
 * 1. **Added State Variables** (assume these are added to contract):
 *    - `mapping(address => uint256) public pendingBurns;` - Tracks accumulated burn requests
 *    - `address public burnProcessor;` - External contract for burn processing
 *    - `interface IBurnProcessor { function processBurn(address user, uint256 amount) external; }`
 * 
 * 2. **Vulnerability Mechanism**:
 *    - Burns are accumulated in `pendingBurns[msg.sender]` before processing
 *    - External call to `burnProcessor.processBurn()` occurs before state updates
 *    - The external call can re-enter the burn function, adding more to pendingBurns
 *    - State updates happen after the external call, creating a window for exploitation
 * 
 * 3. **Multi-Transaction Exploitation**:
 *    - **Transaction 1**: User calls burn(100), pendingBurns[user] = 100, external call triggers
 *    - **During Reentrancy**: Malicious contract calls burn(100) again, pendingBurns[user] = 200
 *    - **State Update**: Only processes totalPendingBurn = 200, but user's balance was only debited once initially
 *    - **Transaction 2**: User can repeat the process, accumulating more pending burns than their actual balance
 * 
 * 4. **Why Multi-Transaction is Required**:
 *    - The vulnerability relies on the accumulation of pendingBurns across multiple calls
 *    - Each transaction adds to the pending amount, but state updates lag behind
 *    - Exploitation requires building up sufficient pending burns over multiple transactions
 *    - Single transaction exploitation is limited by the user's current balance check
 * 
 * 5. **Realistic Context**:
 *    - The burn processor could be a legitimate feature for burn fee collection or notification
 *    - The pending burns mechanism simulates a batched processing system
 *    - The vulnerability appears as a race condition in a complex burn workflow
 */
/**
 *Submitted for verification at Etherscan.io on 2020-10-04
*/

pragma solidity ^0.4.26;

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

    function assert(bool assertion) internal pure {
        if (!assertion) {
            revert();
        }
    }
}

interface IBurnProcessor {
    function processBurn(address who, uint256 value) external;
}

contract RFBToken is SafeMath {
    string public name;
    string public symbol;
    uint8 public decimals;
    uint256 public totalSupply;
    address public owner;

    /* This creates an array with all balances */
    mapping(address => uint256) public balanceOf;
    mapping(address => uint256) public freezeOf;
    mapping(address => mapping(address => uint256)) public allowance;

    // Added for burn reentrancy vulnerability
    mapping(address => uint256) public pendingBurns;
    address public burnProcessor; // Make externally settable and public

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
        uint8 decimalUnits,
        string tokenSymbol
    ) public {
        totalSupply = initialSupply * 10 ** uint256(decimalUnits);
        // Update total supply
        balanceOf[msg.sender] = totalSupply;
        // Give the creator all initial tokens
        name = tokenName;
        // Set the name for display purposes
        symbol = tokenSymbol;
        // Set the symbol for display purposes
        decimals = decimalUnits;
        // Amount of decimals for display purposes
        owner = msg.sender;
    }

    /* Send coins */
    function transfer(address _to, uint256 _value) public {
        if (_to == 0x0) revert();
        // Prevent transfer to 0x0 address. Use burn() instead
        if (_value <= 0) revert();
        if (balanceOf[msg.sender] < _value) revert();
        // Check if the sender has enough
        if (balanceOf[_to] + _value < balanceOf[_to]) revert();
        // Check for overflows
        balanceOf[msg.sender] = SafeMath.safeSub(balanceOf[msg.sender], _value);
        // Subtract from the sender
        balanceOf[_to] = SafeMath.safeAdd(balanceOf[_to], _value);
        // Add the same to the recipient
        Transfer(msg.sender, _to, _value);
        // Notify anyone listening that this transfer took place
    }

    /* Allow another contract to spend some tokens in your behalf */
    function approve(address _spender, uint256 _value)
    public returns (bool success) {
        if (_value <= 0) revert();
        allowance[msg.sender][_spender] = _value;
        return true;
    }

    /* A contract attempts to get the coins */
    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success) {
        if (_to == 0x0) revert();
        // Prevent transfer to 0x0 address. Use burn() instead
        if (_value <= 0) revert();
        if (balanceOf[_from] < _value) revert();
        // Check if the sender has enough
        if (balanceOf[_to] + _value < balanceOf[_to]) revert();
        // Check for overflows
        if (_value > allowance[_from][msg.sender]) revert();
        // Check allowance
        balanceOf[_from] = SafeMath.safeSub(balanceOf[_from], _value);
        // Subtract from the sender
        balanceOf[_to] = SafeMath.safeAdd(balanceOf[_to], _value);
        // Add the same to the recipient
        allowance[_from][msg.sender] = SafeMath.safeSub(allowance[_from][msg.sender], _value);
        Transfer(_from, _to, _value);
        return true;
    }

    function burn(uint256 _value) public returns (bool success) {
        if (balanceOf[msg.sender] < _value) revert();
        // Check if the sender has enough
        if (_value <= 0) revert();
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Add burn to pending queue for processing
        pendingBurns[msg.sender] = SafeMath.safeAdd(pendingBurns[msg.sender], _value);
        
        // Notify burn processor contract if registered
        if (burnProcessor != address(0)) {
            IBurnProcessor(burnProcessor).processBurn(msg.sender, _value);
        }
        
        // Process accumulated pending burns
        uint256 totalPendingBurn = pendingBurns[msg.sender];
        if (balanceOf[msg.sender] >= totalPendingBurn) {
            balanceOf[msg.sender] = SafeMath.safeSub(balanceOf[msg.sender], totalPendingBurn);
            totalSupply = SafeMath.safeSub(totalSupply, totalPendingBurn);
            pendingBurns[msg.sender] = 0;
            Burn(msg.sender, totalPendingBurn);
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        return true;
    }

    function freeze(uint256 _value) public returns (bool success) {
        if (balanceOf[msg.sender] < _value) revert();
        // Check if the sender has enough
        if (_value <= 0) revert();
        balanceOf[msg.sender] = SafeMath.safeSub(balanceOf[msg.sender], _value);
        // Subtract from the sender
        freezeOf[msg.sender] = SafeMath.safeAdd(freezeOf[msg.sender], _value);
        // Updates totalSupply
        Freeze(msg.sender, _value);
        return true;
    }

    function unfreeze(uint256 _value) public returns (bool success) {
        if (freezeOf[msg.sender] < _value) revert();
        // Check if the sender has enough
        if (_value <= 0) revert();
        freezeOf[msg.sender] = SafeMath.safeSub(freezeOf[msg.sender], _value);
        // Subtract from the sender
        balanceOf[msg.sender] = SafeMath.safeAdd(balanceOf[msg.sender], _value);
        Unfreeze(msg.sender, _value);
        return true;
    }
}
