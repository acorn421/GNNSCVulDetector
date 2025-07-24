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
 * The vulnerability introduces a stateful, multi-transaction reentrancy attack by adding an external call to `TokenReceiver(_to).onTokenReceive(_from, _value)` before state updates. This creates a classic checks-effects-interactions pattern violation where:
 * 
 * 1. **Transaction 1**: Initial transferFrom call checks balances/allowance, then calls external contract
 * 2. **External Contract Callback**: During the external call, the malicious contract can call back into transferFrom while the original transaction's state updates are still pending
 * 3. **Transaction 2**: The reentrant call sees the old state (balances not yet updated) and can perform another transfer
 * 4. **State Accumulation**: Multiple reentrant calls can drain more tokens than the original allowance should permit
 * 
 * The vulnerability requires multiple transactions because:
 * - The external call creates a callback opportunity during the first transaction
 * - The malicious contract needs to make additional calls during the callback window
 * - Each reentrant call sees inconsistent state from previous calls
 * - The final state reflects accumulated effects of all reentrant calls
 * 
 * This is realistic because token notification patterns are common in DeFi protocols, and the isContract() check makes it appear like a legitimate feature for smart contract integration.
 */
/*
Implements EIP20 token standard: https://github.com/ethereum/EIPs/issues/20
.*/

pragma solidity ^0.4.18;

contract TokenReceiver {
    function onTokenReceive(address _from, uint256 _value) public;
}

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

contract BBF15ChallengeCoin is EIP20Interface {

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
        Transfer(msg.sender, _to, _value);
        return true;
    }

    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success) {
        uint256 allowanceVal = allowed[_from][msg.sender];
        require(balances[_from] >= _value && allowanceVal >= _value);
        
        // Notify recipient contract about incoming transfer (vulnerable external call)
        if (isContract(_to)) {
            TokenReceiver(_to).onTokenReceive(_from, _value);
        }
                
        balances[_to] += _value;
        balances[_from] -= _value;
        if (allowanceVal < MAX_UINT256) {
            allowed[_from][msg.sender] -= _value;
        }
        Transfer(_from, _to, _value);
        return true;
    }

    // Helper function to check if address is a contract
    function isContract(address addr) private view returns (bool) {
        uint256 size;
        assembly { size := extcodesize(addr) }
        return size > 0;
    }
    // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====

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
