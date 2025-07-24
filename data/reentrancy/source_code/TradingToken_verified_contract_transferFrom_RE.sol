/*
 * ===== SmartInject Injection Details =====
 * Function      : transferFrom
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 3 findings
 * Total Found   : 3 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-benign (SWC-107)
 * 3. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by:
 * 
 * 1. **Added Transfer State Tracking**: Introduced `transfersInProgress` and `pendingTransfers` mappings to track ongoing transfers between transactions
 * 2. **External Call Before State Finalization**: Added `onTokenReceived` callback to recipient contracts before the allowance is updated
 * 3. **State Window Creation**: The external call happens after balance updates but before allowance updates, creating a vulnerable state window
 * 4. **Multi-Transaction Exploitation Path**: The vulnerability requires multiple steps:
 *    - Transaction 1: Attacker sets up malicious recipient contract
 *    - Transaction 2: Victim calls transferFrom, triggering reentrancy during onTokenReceived
 *    - Transaction 3: Attacker exploits the inconsistent state where balances are updated but allowance isn't yet decremented
 * 
 * The exploit works by:
 * 1. Attacker creates a malicious contract implementing ITokenReceiver
 * 2. In the onTokenReceived callback, the malicious contract calls transferFrom again
 * 3. Since allowance hasn't been decremented yet (happens after the external call), the same allowance can be used multiple times
 * 4. The transfersInProgress state persists between transactions, allowing accumulated exploitation
 * 5. Multiple transactions can exploit the same allowance before it's properly decremented
 * 
 * This creates a stateful reentrancy where the vulnerability accumulates across multiple transactions and requires the persistent state changes to be exploitable.
 */
/**
 *Submitted for verification at Etherscan.io on 2018-05-17
*/

// Abstract contract for the full ERC 20 Token standard
// https://github.com/ethereum/EIPs/blob/master/EIPS/eip-20.md
pragma solidity ^0.4.18;

interface ITokenReceiver {
    function onTokenReceived(address _from, uint256 _value) external;
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

/*
Implements EIP20 token standard: https://github.com/ethereum/EIPs/blob/master/EIPS/eip-20.md
.*/

pragma solidity ^0.4.18;

contract TradingToken is EIP20Interface {

    uint256 constant private MAX_UINT256 = 2**256 - 1;
    mapping (address => uint256) public balances;
    mapping (address => mapping (address => uint256)) public allowed;
    mapping (address => mapping (address => bool)) public transfersInProgress;
    mapping (address => mapping (address => uint256)) public pendingTransfers;

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

    function isContract(address addr) internal view returns (bool) {
        uint256 size;
        assembly { size := extcodesize(addr) }
        return size > 0;
    }

    function transfer(address _to, uint256 _value) public returns (bool success) {
        require(balances[msg.sender] >= _value);
        balances[msg.sender] -= _value;
        balances[_to] += _value;
        Transfer(msg.sender, _to, _value); //solhint-disable-line indent, no-unused-vars
        return true;
    }

    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
    // The vulnerable implementation as per the error-injected interface
    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success) {
        uint256 allowance_ = allowed[_from][msg.sender];
        require(balances[_from] >= _value && allowance_ >= _value);
        transfersInProgress[_from][msg.sender] = true;
        pendingTransfers[_from][_to] += _value;
        balances[_to] += _value;
        balances[_from] -= _value;
        if (isContract(_to)) {
            ITokenReceiver(_to).onTokenReceived(_from, _value);
        }
        if (allowance_ < MAX_UINT256) {
            allowed[_from][msg.sender] -= _value;
        }
        transfersInProgress[_from][msg.sender] = false;
        pendingTransfers[_from][_to] = 0;
        Transfer(_from, _to, _value); //solhint-disable-line indent, no-unused-vars
        return true;
    }
    // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====

    function balanceOf(address _owner) public view returns (uint256 balance) {
        return balances[_owner];
    }

    function approve(address _spender, uint256 _value) public returns (bool success) {
        allowed[msg.sender][_spender] = _value;
        Approval(msg.sender, _spender, _value); //solhint-disable-line indent, no-unused-vars
        return true;
    }

    function allowance(address _owner, address _spender) public view returns (uint256 remaining) {
        return allowed[_owner][_spender];
    }
}
