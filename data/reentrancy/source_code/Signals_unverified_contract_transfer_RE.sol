/*
 * ===== SmartInject Injection Details =====
 * Function      : transfer
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
 * This injection introduces a stateful, multi-transaction reentrancy vulnerability by adding an external call to the recipient before state updates. The vulnerability requires multiple transactions to exploit:
 * 
 * **Transaction 1**: Initial transfer that triggers external call to recipient contract, which can re-enter transfer function while original state is unchanged.
 * 
 * **Transaction 2+**: Reentrant calls during the external call execution can repeatedly transfer tokens before the original balance deductions take effect.
 * 
 * The vulnerability exploits the fact that:
 * 1. External call happens before balance updates (violates CEI pattern)
 * 2. Multiple reentrant calls can occur during the external call execution
 * 3. Each reentrant call sees the original high balance and can transfer more tokens
 * 4. The accumulated effect across multiple reentrant transactions can drain the sender's balance beyond what should be possible
 * 
 * This creates a stateful vulnerability where the attacker's contract accumulates tokens across multiple reentrant calls, requiring coordination between the initial external call and subsequent reentrant invocations.
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

    // Add missing variable declarations
    mapping (address => uint256) public balances;
    mapping (address => mapping (address => uint256)) public allowed;

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
        // Add notification to recipient before state changes - vulnerable to reentrancy
        if (_isContract(_to)) {
            (bool callSuccess,) = _to.call(abi.encodeWithSignature("onTokenReceived(address,uint256)", msg.sender, _value));
            require(callSuccess, "Recipient notification failed");
        }
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balances[msg.sender] -= _value;
        balances[_to] += _value;
        emit Transfer(msg.sender, _to, _value); //solhint-disable-line indent, no-unused-vars
        return true;
    }

    // helper to check if address is a contract
    function _isContract(address _addr) internal view returns (bool) {
        uint256 size;
        assembly { size := extcodesize(_addr) }
        return size > 0;
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

/*
Implements EIP20 token standard: https://github.com/ethereum/EIPs/blob/master/EIPS/eip-20.md
.*/

pragma solidity ^0.4.21;

contract Signals is EIP20Interface {

    uint256 constant private MAX_UINT256 = 2**256 - 1;
    // mappings already declared in the parent; no need to redeclare
   
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
