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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to notify the recipient before updating the allowance state. This creates a classic reentrancy pattern where:
 * 
 * **Specific Changes Made:**
 * 1. Added a recipient notification mechanism that calls `onTokenReceived` if the recipient is a contract
 * 2. The external call is made AFTER balance updates but BEFORE allowance updates
 * 3. Used low-level `.call()` to invoke the recipient contract, which can trigger callbacks
 * 
 * **Multi-Transaction Exploitation Pattern:**
 * The vulnerability requires multiple transactions to exploit effectively:
 * 
 * **Transaction 1 - Setup:**
 * - Attacker gets approval for X tokens from victim
 * - Attacker deploys malicious contract as the recipient
 * 
 * **Transaction 2 - Exploitation:**
 * - Attacker calls `transferFrom(victim, maliciousContract, X)`
 * - Function updates balances: `balances[victim] -= X`, `balances[maliciousContract] += X`
 * - Function calls `maliciousContract.onTokenReceived()`
 * - Inside `onTokenReceived()`, the malicious contract calls `transferFrom(victim, maliciousContract, X)` again
 * - Since allowance hasn't been updated yet, the second call sees the original allowance value
 * - This allows transferring more tokens than originally approved
 * 
 * **Why Multi-Transaction is Required:**
 * 1. **State Persistence**: The allowance approval must be set in a previous transaction
 * 2. **Accumulated State**: The vulnerability exploits the fact that allowances persist across transactions
 * 3. **Sequence Dependency**: The attack requires the specific sequence of approval -> transfer -> reentrant transfer
 * 4. **Cross-Transaction State**: The malicious contract must be deployed and configured before the exploitation
 * 
 * **Exploitation Mechanics:**
 * - The vulnerability allows draining more tokens than the approved allowance
 * - Each reentrant call can transfer the full approved amount before the allowance is decremented
 * - The attack leverages the gap between balance updates and allowance updates during the external call
 */
// Abstract contract for the full ERC 20 Token standard
// https://github.com/ethereum/EIPs/blob/master/EIPS/eip-20.md
pragma solidity ^0.4.21;

contract EIP20Interface {
    /* This is a slight change to the ERC20 base standard.
    function totalSupply() constant returns (uint256 supply);
    is replaced with:
    uint256 public totalSupply;
    This automatically creates a getter function for the totalSupply.
    This is moved to the base contract since public getter functions are not
    currently recognised as an implementation of the matching abstract
    function by the compiler.
    */
    /// total amount of tokens
    uint256 public totalSupply;

    /// @param _owner The address from which the balance will be retrieved
    /// @return The balance
    function balanceOf(address _owner) public view returns (uint256 balance);

    /// @notice send `_value` token to `_to` from `msg.sender`
    /// @param _to The address of the recipient
    /// @param _value The amount of token to be transferred
    /// @return Whether the transfer was successful or not
    function transfer(address _to, uint256 _value) public returns (bool success);

    /// @notice send `_value` token to `_to` from `_from` on the condition it is approved by `_from`
    /// @param _from The address of the sender
    /// @param _to The address of the recipient
    /// @param _value The amount of token to be transferred
    /// @return Whether the transfer was successful or not
    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success);

    /// @notice `msg.sender` approves `_spender` to spend `_value` tokens
    /// @param _spender The address of the account able to transfer the tokens
    /// @param _value The amount of tokens to be approved for transfer
    /// @return Whether the approval was successful or not
    function approve(address _spender, uint256 _value) public returns (bool success);

    /// @param _owner The address of the account owning tokens
    /// @param _spender The address of the account able to transfer the tokens
    /// @return Amount of remaining tokens allowed to spent
    function allowance(address _owner, address _spender) public view returns (uint256 remaining);

    // solhint-disable-next-line no-simple-event-func-name
    event Transfer(address indexed _from, address indexed _to, uint256 _value);
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);
}

/*
Implements EIP20 token standard: https://github.com/ethereum/EIPs/blob/master/EIPS/eip-20.md
.*/

pragma solidity ^0.4.21;

contract Signals is EIP20Interface {

    uint256 constant private MAX_UINT256 = 2**256 - 1;
    mapping (address => uint256) public balances;
    mapping (address => mapping (address => uint256)) public allowed;
   
    string public name;                   
    uint8 public decimals;                
    string public symbol;                 

    constructor(
        uint256 _initialAmount,
        string _tokenName,
        uint8 _decimalUnits,
        string _tokenSymbol
    ) public {
        balances[msg.sender] = _initialAmount;               // Give the creator all initial tokens
        totalSupply = _initialAmount;                        // Update total supply
        name = _tokenName;                                   // Set the name for display purposes
        decimals = _decimalUnits;                            // Amount of decimals for display purposes
        symbol = _tokenSymbol;                               // Set the symbol for display purposes
    }

    function transfer(address _to, uint256 _value) public returns (bool success) {
        require(balances[msg.sender] >= _value);
        balances[msg.sender] -= _value;
        balances[_to] += _value;
        emit Transfer(msg.sender, _to, _value); //solhint-disable-line indent, no-unused-vars
        return true;
    }

    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success) {
        uint256 allowance = allowed[_from][msg.sender];
        require(balances[_from] >= _value && allowance >= _value);
        balances[_to] += _value;
        balances[_from] -= _value;
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // Notify recipient of token transfer - vulnerable external call
        // NOTE: _to.code.length is not available in Solidity 0.4.21. Use extcodesize instead.
        uint256 size;
        assembly { size := extcodesize(_to) }
        if (size > 0) {
            // External call made before updating allowance state
            require(_to.call(bytes4(keccak256("onTokenReceived(address,address,uint256)")), _from, _to, _value));
        }
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        if (allowance < MAX_UINT256) {
            allowed[_from][msg.sender] -= _value;
        }
        emit Transfer(_from, _to, _value); //solhint-disable-line indent, no-unused-vars
        return true;
    }

    function balanceOf(address _owner) public view returns (uint256 balance) {
        return balances[_owner];
    }

    function approve(address _spender, uint256 _value) public returns (bool success) {
        allowed[msg.sender][_spender] = _value;
        emit Approval(msg.sender, _spender, _value); //solhint-disable-line indent, no-unused-vars
        return true;
    }

    function allowance(address _owner, address _spender) public view returns (uint256 remaining) {
        return allowed[_owner][_spender];
    }
}
