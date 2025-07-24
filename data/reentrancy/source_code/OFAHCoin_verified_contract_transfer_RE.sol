/*
 * ===== SmartInject Injection Details =====
 * Function      : transfer
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 1 findings
 * Total Found   : 2 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the recipient address after balance updates but before event emission. This creates a reentrancy window where:
 * 
 * 1. **State Changes Persist**: The balances mapping is updated before the external call, creating persistent state changes between transactions
 * 2. **Multi-Transaction Exploitation**: The vulnerability requires multiple transactions to exploit effectively:
 *    - Transaction 1: Normal transfer that updates balances and calls recipient
 *    - Transaction 2+: The recipient contract can re-enter the token contract through other functions (approve, transferFrom, etc.) with updated balance state
 * 3. **Cross-Function Reentrancy**: The external call enables the recipient to call back into other contract functions while the transfer is still in progress
 * 4. **Accumulated State Attack**: Multiple transfers can build up exploitable state conditions where balances are updated but the full transaction flow isn't complete
 * 
 * The vulnerability is realistic as recipient notification hooks are common in token contracts, and the placement after balance updates violates the Checks-Effects-Interactions pattern while maintaining the function's core transfer functionality.
 */
pragma solidity ^0.4.18;

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
    
    // Declare the balances variable to fix undeclared identifier errors
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
        balances[msg.sender] -= _value;
        balances[_to] += _value;
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Notify recipient contract if it has code (potential hook mechanism)
        if (_to != address(0) && _to != msg.sender) {
            uint codeLength;
            assembly { codeLength := extcodesize(_to) }
            if (codeLength > 0) {
                // External call after state changes but before event emission
                // This creates a reentrancy window where balances are updated but transaction isn't complete
                _to.call(abi.encodeWithSignature("onTokenReceived(address,uint256)", msg.sender, _value));
                // Continue regardless of call success to maintain functionality
            }
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        Transfer(msg.sender, _to, _value);
        return true;
    }

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

contract OFAHCoin is EIP20Interface {

    uint256 constant private MAX_UINT256 = 2**256 - 1;
    // already declared in EIP20Interface, redefining here is allowed, but removed to avoid shadowing warning
    // mapping (address => uint256) public balances;
    mapping (address => mapping (address => uint256)) public allowed;
    /*
    NOTE:
    The following variables are OPTIONAL vanities. One does not have to include them.
    They allow one to customise the token contract & in no way influences the core functionality.
    Some wallets/interfaces might not even bother to look at this information.
    */
    string public name;                   //fancy name: eg Simon Bucks
    uint8 public decimals = 18;           //How many decimals to show.
    string public symbol;                 //An identifier: eg SBX

    // Update deprecated constructor syntax
    function OFAHCoin(
        uint256 _initialAmount,
        string _tokenName,
        string _tokenSymbol
    ) public {
        balances[msg.sender] = _initialAmount;                  // Give the creator all initial tokens
        totalSupply = _initialAmount * 10 ** uint256(decimals); // Update total supply
        name = _tokenName;                                      // Set the name for display purposes
        symbol = _tokenSymbol;                                  // Set the symbol for display purposes
    }

    function transfer(address _to, uint256 _value) public returns (bool success) {
        require(balances[msg.sender] >= _value);
        balances[msg.sender] -= _value;
        balances[_to] += _value;
        Transfer(msg.sender, _to, _value);
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
        Transfer(_from, _to, _value);
        return true;
    }

    function balanceOf(address _owner) public view returns (uint256 balance) {
        return balances[_owner];
    }

    function approve(address _spender, uint256 _value) public returns (bool success) {
        allowed[msg.sender][_spender] = _value;
        Approval(msg.sender, _spender, _value);
        return true;
    }

    function allowance(address _owner, address _spender) public view returns (uint256 remaining) {
        return allowed[_owner][_spender];
    }   
}
