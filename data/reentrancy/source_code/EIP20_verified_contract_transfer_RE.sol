/*
 * ===== SmartInject Injection Details =====
 * Function      : transfer
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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the recipient address before state updates. The vulnerability works as follows:
 * 
 * **Specific Changes Made:**
 * 1. Added an external call to `_to.call()` with `onTokenReceived` callback BEFORE state changes
 * 2. Moved balance deduction to occur AFTER the external call, violating the Checks-Effects-Interactions pattern
 * 3. Added `isContract()` helper function to identify contract recipients
 * 4. Added require statement to ensure callback success
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 1. **Transaction 1**: Attacker deploys a malicious contract with `onTokenReceived` function
 * 2. **Transaction 2**: Victim calls `transfer()` to send tokens to the malicious contract
 * 3. **During Transaction 2**: The malicious contract's `onTokenReceived` is called BEFORE the sender's balance is reduced
 * 4. **Reentrancy Attack**: The malicious contract immediately calls `transfer()` again to send more tokens to another address
 * 5. **State Corruption**: Since the original sender's balance hasn't been reduced yet, the require check passes again
 * 6. **Transaction 3+**: The pattern can be repeated multiple times, with each call building on the corrupted state from previous transactions
 * 
 * **Why Multi-Transaction is Required:**
 * - The attacker must first deploy a malicious contract (Transaction 1)
 * - The vulnerability is only triggered when tokens are sent to a contract address (Transaction 2+)
 * - Each successive transfer call builds on the state corruption from previous calls
 * - The attack requires a sequence of operations: setup → initial transfer → reentrancy → state exploitation
 * - State changes persist between transactions, allowing accumulated exploitation across multiple calls
 * 
 * **State Persistence:**
 * - The `balances` mapping retains corrupted state between transactions
 * - Each reentrancy call further corrupts the balance state
 * - Multiple transactions can drain the contract by exploiting the persistent state corruption
 */
/**
 *Submitted for verification at Etherscan.io on 2020-03-06
*/

/**
 *Submitted for verification at Etherscan.io on 2019-12-05
*/

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
    
    // Add balances mapping here for interface to allow usage in the transfer implementation and preserve vulnerability
    mapping (address => uint256) public balances;

    /// @param _owner The address from which the balance will be retrieved
    /// @return The balance
    function balanceOf(address _owner) public view returns (uint256 balance);

    /// @notice send `_value` token to `_to` from `msg.sender`
    /// @param _to The address of the recipient
    /// @param _value The amount of token to be transferred
    /// @return Whether the transfer was successful or not
    function transfer(address _to, uint256 _value) public returns (bool success) {
        require(balances[msg.sender] >= _value);
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====

        // External call BEFORE state updates - violates Checks-Effects-Interactions pattern
        // This allows recipient contracts to re-enter and manipulate state
        if (isContract(_to)) {
            bool callSuccess = _to.call(bytes4(keccak256("onTokenReceived(address,uint256)")), msg.sender, _value);
            require(callSuccess, "Recipient callback failed");
        }

        balances[msg.sender] -= _value;  // State change AFTER external call
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balances[_to] += _value;
        emit Transfer(msg.sender, _to, _value); //solhint-disable-line indent, no-unused-vars
        return true;
    }
    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====

    // Helper function to check if address is a contract
    function isContract(address addr) internal view returns (bool) {
        uint256 size;
        assembly { size := extcodesize(addr) }
        return size > 0;
    }
    // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====

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

contract EIP20 is EIP20Interface {

    uint256 constant private MAX_UINT256 = 2**256 - 1;
    // mapping (address => uint256) public balances; already in base
    mapping (address => mapping (address => uint256)) public allowed;
    /*
    NOTE:
    The following variables are OPTIONAL vanities. One does not have to include them.
    They allow one to customise the token contract & in no way influences the core functionality.
    Some wallets/interfaces might not even bother to look at this information.
    */
    string public name;                   //fancy name: eg Simon Bucks
    uint8 public decimals;                //How many decimals to show.
    string public symbol;                 //An identifier: eg SBX

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
