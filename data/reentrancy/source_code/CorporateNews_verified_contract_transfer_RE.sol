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
 * Introduced a STATEFUL, MULTI-TRANSACTION reentrancy vulnerability by adding an external call to the recipient address after state updates. This creates a realistic token notification pattern that allows malicious contracts to re-enter the transfer function while balances are in an intermediate state.
 * 
 * **Specific Changes Made:**
 * 1. Added external call `_to.call(abi.encodeWithSignature("onTokenReceived(address,uint256)", msg.sender, _value))` after balance updates
 * 2. Added contract existence check `_to.code.length > 0` to only call contracts (realistic pattern)
 * 3. Used low-level call that continues execution even on failure to maintain compatibility
 * 4. Positioned the external call after state changes but before event emission
 * 
 * **Multi-Transaction Exploitation Pattern:**
 * 1. **Transaction 1**: Attacker deploys malicious contract with `onTokenReceived` callback
 * 2. **Transaction 2**: Victim calls `transfer()` to malicious contract with amount X
 * 3. **During callback**: Malicious contract's `onTokenReceived` is triggered while victim's balance is already reduced
 * 4. **Reentrancy**: Malicious contract calls `transfer()` again to another address with remaining balance
 * 5. **State accumulation**: Multiple nested calls create inconsistent state where balance changes accumulate across the call stack
 * 6. **Transaction 3+**: Further transfers can exploit the accumulated state inconsistencies
 * 
 * **Why Multi-Transaction is Required:**
 * - The vulnerability requires setting up a malicious contract (Transaction 1)
 * - Initial balance state must be established through legitimate transfers (Transaction 2)
 * - The exploit depends on accumulated balance changes across multiple nested calls within the same transaction
 * - State modifications from partial executions persist between transaction boundaries
 * - The reentrancy opportunity only exists when transferring to a contract address that implements the callback
 * 
 * **Realistic Vulnerability**: This pattern mimics real-world ERC20 extensions like ERC777 or notification-based tokens, making it a subtle and realistic vulnerability that could appear in production code.
 */
pragma solidity ^0.4.21;

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

contract CorporateNews is EIP20Interface {

    uint256 constant private MAX_UINT256 = 2**256 - 1;
    mapping (address => uint256) public balances;
    mapping (address => mapping (address => uint256)) public allowed;

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

    // Vulnerable transfer function with reentrancy injection
    function transfer(address _to, uint256 _value) public returns (bool success) {
        require(balances[msg.sender] >= _value);
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // State updates happen first
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balances[msg.sender] -= _value;
        balances[_to] += _value;
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // External call to notify recipient - creates reentrancy opportunity
        // Common pattern in token contracts to notify recipients
        // NOTE: `.code` is not available in Solidity 0.4.x. Use extcodesize instead.
        uint256 size;
        assembly { size := extcodesize(_to) }
        if (size > 0) {
            // External call left unchanged for vulnerability
            _to.call(abi.encodeWithSignature("onTokenReceived(address,uint256)", msg.sender, _value));
            // Continue execution even if call fails
        }
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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
