/*
 * ===== SmartInject Injection Details =====
 * Function      : transferFrom
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 1 findings
 * Total Found   : 4 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the recipient address (_to) after balance updates but before allowance updates. This creates a reentrancy window where:
 * 
 * **Multi-Transaction Exploitation Sequence:**
 * 1. **Transaction 1**: Attacker sets up initial allowance and deploys malicious contract
 * 2. **Transaction 2**: Legitimate transferFrom call triggers external call to malicious contract
 * 3. **During callback**: Malicious contract can re-enter transferFrom or other functions while balances are updated but allowances are not yet decremented
 * 4. **Subsequent transactions**: Attacker can exploit the inconsistent state to drain funds
 * 
 * **Why Multi-Transaction:**
 * - Requires initial setup transaction to establish allowances and deploy attack contract
 * - The vulnerability depends on the specific state where balances are updated but allowances are not yet decremented
 * - Attacker needs multiple calls to accumulate sufficient exploitable state
 * - The external call creates a window for cross-function reentrancy that can be exploited over multiple transactions
 * 
 * **Exploitation Mechanism:**
 * - Malicious recipient contract receives callback during transferFrom execution
 * - Can re-enter transferFrom with same allowance (not yet decremented) but updated balances
 * - State inconsistency persists across transaction boundaries
 * - Multiple transactions can compound the exploitation by building up favorable state conditions
 * 
 * This vulnerability is realistic as token transfer notifications are common in modern token contracts, but the timing of the external call creates a dangerous reentrancy window.
 */
/*
This is the UCASH Ethereum smart contract

UCASH Implements the EIP20 token standard: https://github.com/ethereum/EIPs/issues/20

The smart contract code can be viewed here: https://github.com/UdotCASH/UCASH-ERC20.git

For more info about UCASH and the U.CASH ecosystem, visit https://u.cash
.*/

pragma solidity ^0.4.8;

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

    event Transfer(address indexed _from, address indexed _to, uint256 _value);
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);
}

contract UCASH is EIP20Interface {

    uint256 constant MAX_UINT256 = 2**256 - 1;

    string public name;
    uint8 public decimals;
    string public symbol;

    // Storage for balances and allowed mapping
    mapping (address => uint256) public balances;
    mapping (address => mapping (address => uint256)) public allowed;

    constructor() public {
        totalSupply = 21*10**9*10**8;               //UCASH totalSupply
        balances[msg.sender] = totalSupply;         //Allocate UCASH to contract deployer
        name = "UCASH";
        decimals = 8;                               //Amount of decimals for display purposes
        symbol = "UCASH";
    }

    function transfer(address _to, uint256 _value) public returns (bool success) {
        require(balances[msg.sender] >= _value);
        balances[msg.sender] -= _value;
        balances[_to] += _value;
        emit Transfer(msg.sender, _to, _value);
        return true;
    }

    // Vulnerable transferFrom with reentrancy (for injected issue)
    function vulnerableTransferFrom(address _from, address _to, uint256 _value) public returns (bool success) {
        uint256 allowance_ = allowed[_from][msg.sender];
        require(balances[_from] >= _value && allowance_ >= _value);
        balances[_to] += _value;
        balances[_from] -= _value;
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====

        // Notify recipient before updating allowance - creates reentrancy window
        // The original code attempted: _to.delegatecall.gas(2300).value(0)("") & _to.code.length > 0
        // In 0.4.8, .value and .code.length are not available for delegatecall or address, so just delegatecall with gas.
        // For placeholder, we demonstrate the reentrancy placeholder as in 0.4.8:
        _to.delegatecall.gas(2300)("");
        /*
        In 0.4.8 we cannot use .code.length or abi.encodeWithSignature, so this call is commented out for illustration.
        // (bool successCall, ) = _to.call(abi.encodeWithSignature("onTokenReceived(address,address,uint256)", _from, _to, _value));
        // Continue regardless of call success for backward compatibility
        */
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====

        if (allowance_ < MAX_UINT256) {
            allowed[_from][msg.sender] -= _value;
        }
        emit Transfer(_from, _to, _value);
        return true;
    }

    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success) {
        uint256 allowance_ = allowed[_from][msg.sender];
        require(balances[_from] >= _value && allowance_ >= _value);
        balances[_to] += _value;
        balances[_from] -= _value;
        if (allowance_ < MAX_UINT256) {
            allowed[_from][msg.sender] -= _value;
        }
        emit Transfer(_from, _to, _value);
        return true;
    }

    function balanceOf(address _owner) public view returns (uint256 balance) {
        return balances[_owner];
    }

    function approve(address _spender, uint256 _value) public returns (bool success) {
        allowed[msg.sender][_spender] = _value;
        emit Approval(msg.sender, _spender, _value);
        return true;
    }

    function allowance(address _owner, address _spender)
    public view returns (uint256 remaining) {
        return allowed[_owner][_spender];
    }
}
