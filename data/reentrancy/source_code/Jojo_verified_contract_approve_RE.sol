/*
 * ===== SmartInject Injection Details =====
 * Function      : approve
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
 * 1. reentrancy-benign (SWC-107)
 *
 * === Description ===
 * **STATEFUL, MULTI-TRANSACTION REENTRANCY VULNERABILITY**
 * 
 * **Specific Changes Made:**
 * 1. **Added external call before state update**: Introduced a call to `tokenRecipient(_spender).receiveApproval()` before the allowance state is updated
 * 2. **Violated CEI pattern**: The external call occurs before the critical state change (allowance update)
 * 3. **Added contract existence check**: Used `_spender.code.length > 0` to determine if the spender is a contract
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 
 * **Transaction 1 (Initial Setup):**
 * - User calls `approve(maliciousContract, 1000)`
 * - External call to `maliciousContract.receiveApproval()` is made
 * - During this callback, the malicious contract can call `approve()` again since allowance hasn't been updated yet
 * - This creates inconsistent allowance states across multiple approve calls
 * 
 * **Transaction 2 (Exploitation):**
 * - The malicious contract can now exploit the accumulated allowance inconsistencies
 * - Multiple reentrancy calls in Transaction 1 may have created allowance values that don't match expected behavior
 * - Subsequent `transferFrom` calls can exploit these inconsistent allowances
 * 
 * **Why Multi-Transaction is Required:**
 * 1. **State Accumulation**: The vulnerability builds up through multiple reentrant calls within the first transaction, creating persistent state inconsistencies
 * 2. **Exploitation Phase**: The actual exploitation occurs in subsequent transactions when the malicious contract uses the accumulated allowance inconsistencies
 * 3. **Persistent State**: The allowance mapping changes persist between transactions, enabling the exploit to span multiple transaction boundaries
 * 4. **Complex Attack Pattern**: The attack requires setting up the inconsistent state first, then exploiting it later - impossible in a single atomic operation
 * 
 * **Exploitation Impact:**
 * - Attacker can potentially gain higher allowances than intended
 * - Multiple approve calls during reentrancy can compound allowance values
 * - Subsequent transferFrom operations can drain more tokens than originally approved
 * - The vulnerability creates a window for privilege escalation across transaction boundaries
 */
pragma solidity ^0.4.8;
contract tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData); }

contract Jojo {
    /* Public variables of the token */
    string public name;
    string public symbol;
    uint8 public decimals;
    uint256 public totalSupply;

    /* This creates an array with all balances */
    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;

    /* This generates a public event on the blockchain that will notify clients */
    event Transfer(address indexed from, address indexed to, uint256 value);

    /* Initializes contract with initial supply tokens to the creator of the contract */
    function Jojo(
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
    }

    /* Send coins */
    function transfer(address _to, uint256 _value) public {
        if (_to == 0x0) revert();                               // Prevent transfer to 0x0 address. Use burn() instead
        if (balanceOf[msg.sender] < _value) revert();           // Check if the sender has enough
        if (balanceOf[_to] + _value < balanceOf[_to]) revert(); // Check for overflows
        balanceOf[msg.sender] -= _value;                        // Subtract from the sender
        balanceOf[_to] += _value;                               // Add the same to the recipient
        emit Transfer(msg.sender, _to, _value);                 // Notify anyone listening that this transfer took place
    }

    /* Allow another contract to spend some tokens in your behalf */
    function approve(address _spender, uint256 _value)
        public
        returns (bool success) {
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        /* Since Solidity 0.4.8 doesn't have .code, check if it's a contract by extcodesize */
        uint256 codeLength;
        assembly { codeLength := extcodesize(_spender) }
        if (codeLength > 0) {
            tokenRecipient(_spender).receiveApproval(msg.sender, _value, this, "");
        }
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        allowance[msg.sender][_spender] = _value;
        return true;
    }

    /* Approve and then communicate the approved contract in a single tx */
    function approveAndCall(address _spender, uint256 _value, bytes _extraData)
        public returns (bool success) {
        tokenRecipient spender = tokenRecipient(_spender);
        if (approve(_spender, _value)) {
            spender.receiveApproval(msg.sender, _value, this, _extraData);
            return true;
        }
    }        

    /* A contract attempts to get the coins */
    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success) {
        if (_to == 0x0) revert();                                // Prevent transfer to 0x0 address. Use burn() instead
        if (balanceOf[_from] < _value) revert();                 // Check if the sender has enough
        if (balanceOf[_to] + _value < balanceOf[_to]) revert();  // Check for overflows
        if (_value > allowance[_from][msg.sender]) revert();     // Check allowance
        balanceOf[_from] -= _value;                              // Subtract from the sender
        balanceOf[_to] += _value;                                // Add the same to the recipient
        allowance[_from][msg.sender] -= _value;
        emit Transfer(_from, _to, _value);
        return true;
    }
}
