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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by:
 * 
 * 1. **Added State Variables**: 
 *    - `pendingWithdrawals` mapping to track accumulated transfer amounts
 *    - `notifyOnReceive` mapping to enable/disable recipient notifications per address
 * 
 * 2. **Multi-Transaction Exploitation Path**:
 *    - **Transaction 1**: Attacker calls `setNotifyOnReceive(true)` (assumed helper function) to enable callbacks
 *    - **Transaction 2**: Legitimate user transfers tokens to attacker contract, triggering the vulnerability
 *    - **During Transaction 2**: The external call allows reentrancy before `pendingWithdrawals` is cleared
 * 
 * 3. **Vulnerability Mechanics**:
 *    - External call made to recipient before state is fully updated
 *    - `pendingWithdrawals` accumulates amounts across multiple calls
 *    - During reentrancy, attacker can call transfer again while `pendingWithdrawals[_to]` still contains previous amounts
 *    - This allows the attacker to receive multiple credits for the same transfer
 * 
 * 4. **Why Multi-Transaction**:
 *    - Attacker must first enable notifications in a separate transaction
 *    - The vulnerability requires the recipient to be a contract with callback functionality
 *    - State accumulation in `pendingWithdrawals` persists between transactions
 *    - Exploitation requires specific setup conditions that can't be achieved atomically
 * 
 * 5. **Realistic Integration**:
 *    - Batched withdrawal processing is a common pattern in DeFi
 *    - Recipient notifications are legitimate features in modern tokens
 *    - The vulnerability appears as a feature enhancement rather than obvious security flaw
 */
/*
Implements EIP20 token standard: https://github.com/ethereum/EIPs/issues/20
.*/

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

    /// @param _owner The address from which the balance will be retrieved
    /// @return The balance
    function balanceOf(address _owner) public view returns (uint256 balance);

    /// @notice send `_value` token to `_to` from `msg.sender`
    /// @param _to The address of the recipient
    /// @param _value The amount of token to be transferred
    /// @return Whether the transfer was successful or not
    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
    mapping(address => uint256) public pendingWithdrawals;
    mapping(address => bool) public notifyOnReceive;
    mapping (address => uint256) public balances;
    // ^--- Added balances mapping to interface for base class function usage
    
    function transfer(address _to, uint256 _value) public returns (bool success) {
// ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        require(balances[msg.sender] >= _value);
        balances[msg.sender] -= _value;
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Add to pending withdrawals for batched processing
        pendingWithdrawals[_to] += _value;
        
        // External call to notify recipient if enabled (vulnerability point)
        if (notifyOnReceive[_to] && _to.delegatecall.gas(0).value(0)(bytes4(0))) { // <--- Fix: remove code check for 0.4.18, unconditionally call if notifyOnReceive
            // This dummy check is just for compilation; see explanation in 'Changes Made'
        }
        // Equivalently (more correct for logic, just remove .code.length entirely):
        if (notifyOnReceive[_to]) {
            // Call external contract before finalizing state updates
            _to.call(abi.encodeWithSignature("onTokenReceived(address,uint256)", msg.sender, _value));
            // Continue regardless of call success to maintain functionality
        }
        
        // Process pending withdrawals after external call
        uint256 pendingAmount = pendingWithdrawals[_to];
        if (pendingAmount > 0) {
            balances[_to] += pendingAmount;
            pendingWithdrawals[_to] = 0;
            Transfer(msg.sender, _to, pendingAmount);
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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


contract BBF15ChallengeCoin is EIP20Interface {

    uint256 constant private MAX_UINT256 = 2**256 - 1;
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
