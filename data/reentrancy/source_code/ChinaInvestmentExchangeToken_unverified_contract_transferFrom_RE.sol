/*
 * ===== SmartInject Injection Details =====
 * Function      : transferFrom
 * Vulnerability : Reentrancy
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 0 issues
 * Retry Count   : 0
 *
 * === Description ===
 * This modification introduces a stateful, multi-transaction reentrancy vulnerability by:
 * 
 * 1. **Adding pending transfer tracking**: A new state variable `pendingTransfers[_from][msg.sender]` tracks transfers in progress across multiple transactions
 * 2. **External call before allowance update**: Added `ITokenReceiver(_to).onTokenReceived()` call after balance updates but before allowance reduction
 * 3. **State update vulnerability**: The allowance is only reduced AFTER the external call, creating a reentrancy window
 * 4. **Multi-transaction exploit path**: 
 *    - Transaction 1: Initial transferFrom call sets pendingTransfers and calls external contract
 *    - Transaction 2: External contract can call transferFrom again during onTokenReceived callback
 *    - The allowance hasn't been reduced yet, so the second call can drain more tokens
 *    - Multiple reentrant calls can accumulate pending transfers before any allowance updates
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 1. **Setup Phase**: Attacker deploys malicious contract that implements ITokenReceiver
 * 2. **Transaction 1**: Attacker calls transferFrom with their malicious contract as recipient
 * 3. **Reentrant Phase**: During onTokenReceived callback, the malicious contract immediately calls transferFrom again (same allowance still available)
 * 4. **State Accumulation**: Multiple reentrant calls can occur, each adding to pendingTransfers but not reducing allowance until after all calls complete
 * 5. **Exploitation**: Attacker can transfer more tokens than their allowance should permit by exploiting the delayed allowance update
 * 
 * The vulnerability requires multiple function calls and state accumulation across transactions to be effective, making it a genuine multi-transaction reentrancy attack.
 */
// Abstract contract for the full ERC 20 Token standard
// https://github.com/ethereum/EIPs/blob/master/EIPS/eip-20.md
pragma solidity ^0.4.18;

interface ITokenReceiver {
    function onTokenReceived(address _from, uint256 _value) external;
}

contract EIP20Interface {
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
    // Move vulnerable implementation to the child contract, keep only the declaration here
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

contract ChinaInvestmentExchangeToken is EIP20Interface {

    uint256 constant private MAX_UINT256 = 2**256 - 1;
    mapping (address => uint256) public balances;
    mapping (address => mapping (address => uint256)) public allowed;
    mapping (address => mapping (address => uint256)) public pendingTransfers;

    string public name;                   //fancy name: eg Simon Bucks
    uint8 public decimals;                //How many decimals to show.
    string public symbol;                 //An identifier: eg SBX

    constructor(
        uint256 _initialAmount,
        string _tokenName,
        uint8 _decimalUnits,
        string _tokenSymbol
    ) public {
        balances[msg.sender] = _initialAmount;
        totalSupply = _initialAmount;                        
        name = _tokenName;                                   
        decimals = _decimalUnits;                            
        symbol = _tokenSymbol;                               
    }

    function transfer(address _to, uint256 _value) public returns (bool success) {
        require(balances[msg.sender] >= _value);
        balances[msg.sender] -= _value;
        balances[_to] += _value;
        Transfer(msg.sender, _to, _value);
        return true;
    }

    // Vulnerable implementation here in the child contract instead of the interface
    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success) {
        uint256 allowance = allowed[_from][msg.sender];
        require(balances[_from] >= _value && allowance >= _value);
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Add pending transfer tracking for multi-transaction vulnerability
        pendingTransfers[_from][msg.sender] += _value;
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balances[_to] += _value;
        balances[_from] -= _value;
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // External call before allowance update - creates reentrancy opportunity
        if (_to.code.length > 0) {
            ITokenReceiver(_to).onTokenReceived(_from, _value);
        }
        
        // State update after external call - vulnerable to reentrancy
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        if (allowance < MAX_UINT256) {
            allowed[_from][msg.sender] -= _value;
        }
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Clear pending transfer only after successful completion
        pendingTransfers[_from][msg.sender] -= _value;
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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
