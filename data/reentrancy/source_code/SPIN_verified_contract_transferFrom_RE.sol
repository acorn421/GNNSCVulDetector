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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to recipient contracts before completing all state updates. The vulnerability allows malicious contracts to re-enter the transferFrom function while the sender's balance and allowance are still in an inconsistent state, enabling double-spending attacks that require multiple transactions to set up and exploit.
 * 
 * **Specific Changes Made:**
 * 
 * 1. **External Call Injection**: Added `ITokenReceiver(_to).onTokenReceived(_from, _value, "")` callback to notify recipient contracts about incoming transfers
 * 2. **State Update Reordering**: Moved the recipient balance update before the external call, but kept sender balance and allowance updates after the external call
 * 3. **Contract Detection**: Added `isContract()` helper function to determine when to make the external call
 * 4. **Violation of CEI Pattern**: The function now violates the Checks-Effects-Interactions pattern by placing external calls between state updates
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 
 * **Transaction 1 (Setup)**: 
 * - Attacker approves malicious contract for large allowance
 * - Attacker deploys malicious contract that implements ITokenReceiver
 * 
 * **Transaction 2 (Exploitation)**:
 * - Malicious contract calls transferFrom to transfer tokens from victim to itself
 * - During onTokenReceived callback, contract re-enters transferFrom
 * - On re-entrance, victim's balance hasn't been updated yet, and allowance is still available
 * - Second transferFrom call succeeds, effectively double-spending the allowance
 * 
 * **Why Multi-Transaction Nature is Critical:**
 * 
 * 1. **State Accumulation**: The vulnerability requires pre-existing allowance state from a previous approve() transaction
 * 2. **Contract Deployment**: The malicious receiving contract must be deployed in a separate transaction
 * 3. **Sequential Exploitation**: The attack requires the initial transferFrom call to trigger the callback, which then enables the re-entrant call
 * 4. **Allowance Consumption**: Each successful re-entrant call consumes allowance, requiring multiple transactions to fully exploit large allowances
 * 
 * **Technical Vulnerability Details:**
 * 
 * - **Race Condition**: Sender balance and allowance updates occur after external call
 * - **State Inconsistency**: Between the external call and final state updates, the contract is in an inconsistent state
 * - **Reentrancy Window**: The external call creates a window for re-entrance before critical state updates
 * - **Double-Spending**: Allows spending the same allowance multiple times across re-entrant calls
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

// Minimal interface for token receiver
interface ITokenReceiver {
    function onTokenReceived(address _from, uint256 _value, bytes _extraData) external;
}

contract SPIN is SafeMath {
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
        string tokenSymbol
    ) public {
        totalSupply = initialSupply * 10 ** uint256(decimals);                        // Update total supply
        balanceOf[msg.sender] = totalSupply;              // Give the creator all initial tokens
        name = tokenName;                                   // Set the name for display purposes
        symbol = tokenSymbol;                               // Set the symbol for display purposes
        owner = msg.sender;
    }

    /* Send coins */
    function transfer(address _to, uint256 _value) public {
        require(_to != 0x0);
        require(_value > 0);
        require(balanceOf[msg.sender] >= _value);
        require(balanceOf[_to] + _value > balanceOf[_to]);
        balanceOf[msg.sender] = SafeMath.safeSub(balanceOf[msg.sender], _value);                     // Subtract from the sender
        balanceOf[_to] = SafeMath.safeAdd(balanceOf[_to], _value);                            // Add the same to the recipient
        Transfer(msg.sender, _to, _value);                   // Notify anyone listening that this transfer took place
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
        require(balanceOf[_to] + _value > balanceOf[_to]);
        require(_value <= allowance[_from][msg.sender]);
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Update recipient balance first
        balanceOf[_to] = SafeMath.safeAdd(balanceOf[_to], _value);
        
        // Notify recipient contract about incoming transfer (external call before state finalization)
        if (isContract(_to)) {
            ITokenReceiver(_to).onTokenReceived(_from, _value, "");
        }
        
        // Update sender balance after external call
        balanceOf[_from] = SafeMath.safeSub(balanceOf[_from], _value);
        // Update allowance after external call
        allowance[_from][msg.sender] = SafeMath.safeSub(allowance[_from][msg.sender], _value);
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        Transfer(_from, _to, _value);
        return true;
    }
    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
    
    // Helper function to check if address is contract
    function isContract(address addr) internal view returns (bool) {
        uint256 size;
        assembly { size := extcodesize(addr) }
        return size > 0;
    }
    // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====

    function burn(uint256 _value) public returns (bool success) {
        require(balanceOf[msg.sender] >= _value);
        require(_value > 0);
        balanceOf[msg.sender] = SafeMath.safeSub(balanceOf[msg.sender], _value);                      // Subtract from the sender
        totalSupply = SafeMath.safeSub(totalSupply, _value);                                // Updates totalSupply
        Burn(msg.sender, _value);
        return true;
    }

    function freeze(uint256 _value) public returns (bool success) {
        require(balanceOf[msg.sender] >= _value);
        require(_value > 0);
        balanceOf[msg.sender] = SafeMath.safeSub(balanceOf[msg.sender], _value);                      // Subtract from the sender
        freezeOf[msg.sender] = SafeMath.safeAdd(freezeOf[msg.sender], _value);                                // Updates totalSupply
        Freeze(msg.sender, _value);
        return true;
    }

    function unfreeze(uint256 _value) public returns (bool success) {
        require(freezeOf[msg.sender] >= _value);
        require(_value > 0);
        freezeOf[msg.sender] = SafeMath.safeSub(freezeOf[msg.sender], _value);                      // Subtract from the sender
        balanceOf[msg.sender] = SafeMath.safeAdd(balanceOf[msg.sender], _value);
        Unfreeze(msg.sender, _value);
        return true;
    }

    // transfer balance to owner
    function withdrawEther(uint256 amount) public {
        require(msg.sender == owner);
        owner.transfer(amount);
    }

    // can accept ether
    function() public payable {
    }
}
