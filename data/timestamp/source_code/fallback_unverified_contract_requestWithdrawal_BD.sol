/*
 * ===== SmartInject Injection Details =====
 * Function      : requestWithdrawal
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 1 issues
 * Retry Count   : 0
 *
 * === Description ===
 * This vulnerability introduces a multi-transaction timestamp dependence issue in a withdrawal system. The vulnerability requires two transactions: 1) requestWithdrawal() to initiate the withdrawal with a timestamp, and 2) executeWithdrawal() to complete it after a delay. The state persists between transactions via withdrawalRequests and withdrawalTimestamps mappings. Miners can manipulate block.timestamp to bypass the intended delay, allowing premature withdrawals. The vulnerability is stateful because it depends on the stored timestamp from the first transaction and can only be exploited across multiple transactions.
 */
/*
Implements ERC 20 Token standard: https://github.com/ethereum/EIPs/issues/20
*/

pragma solidity ^0.4.2;

// Abstract contract for the full ERC 20 Token standard
// https://github.com/ethereum/EIPs/issues/20
contract Token {
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
    function balanceOf(address _owner) constant returns (uint256 balance);

    /// @notice send `_value` token to `_to` from `msg.sender`
    /// @param _to The address of the recipient
    /// @param _value The amount of token to be transferred
    function transfer(address _to, uint256 _value);

    /// @notice send `_value` token to `_to` from `_from` on the condition it is approved by `_from`
    /// @param _from The address of the sender
    /// @param _to The address of the recipient
    /// @param _value The amount of token to be transferred
    function transferFrom(address _from, address _to, uint256 _value);

    /// @notice `msg.sender` approves `_spender` to spend `_value` tokens
    /// @param _spender The address of the account able to transfer the tokens
    /// @param _value The amount of tokens to be approved for transfer
    /// @return Whether the approval was successful or not
    function approve(address _spender, uint256 _value) returns (bool success);

    /// @param _owner The address of the account owning tokens
    /// @param _spender The address of the account able to transfer the tokens
    /// @return Amount of remaining tokens allowed to spent
    function allowance(address _owner, address _spender) constant returns (uint256 remaining);

    event Transfer(address indexed _from, address indexed _to, uint256 _value);
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);
}

contract Owned {
    address owner;

    function Owned() {
        owner = msg.sender;
    }

    modifier onlyOwner {
        if (msg.sender != owner)
            throw;
        _;
    }
}

contract AliceToken is Token, Owned {

    string public name = "Alice Token";
    uint8 public decimals = 2;
    string public symbol = "ALT";
    string public version = 'ALT 1.0';

    mapping (address => uint256) balances;
    mapping (address => mapping (address => uint256)) allowed;

    // === FALLBACK INJECTION: Timestamp Dependence ===
    // State variables for withdrawal system
    mapping(address => uint256) public withdrawalRequests;
    mapping(address => uint256) public withdrawalTimestamps;
    uint256 public withdrawalDelay = 24 hours;
    // === END FALLBACK INJECTION ===

    function transfer(address _to, uint256 _value) {
        //Default assumes totalSupply can't be over max (2^256 - 1).
        if (balances[msg.sender] >= _value && balances[_to] + _value > balances[_to]) {
            balances[msg.sender] -= _value;
            balances[_to] += _value;
            Transfer(msg.sender, _to, _value);
        } else { throw; }
    }

    function transferFrom(address _from, address _to, uint256 _value) {
        if (balances[_from] >= _value && allowed[_from][msg.sender] >= _value && balances[_to] + _value > balances[_to]) {
            balances[_to] += _value;
            balances[_from] -= _value;
            allowed[_from][msg.sender] -= _value;
            Transfer(_from, _to, _value);
        } else { throw; }
    }

    function balanceOf(address _owner) constant returns (uint256 balance) {
        return balances[_owner];
    }

    function approve(address _spender, uint256 _value) returns (bool success) {
        allowed[msg.sender][_spender] = _value;
        Approval(msg.sender, _spender, _value);
        return true;
    }

    function allowance(address _owner, address _spender) constant returns (uint256 remaining) {
        return allowed[_owner][_spender];
    }

    function mint(address _to, uint256 _value) onlyOwner {
        if (totalSupply + _value < totalSupply) throw;
        totalSupply += _value;
        balances[_to] += _value;

        MintEvent(_to, _value);
    }

    function destroy(address _from, uint256 _value) onlyOwner {
        if (balances[_from] < _value || _value < 0) throw;
        totalSupply -= _value;
        balances[_from] -= _value;
        DestroyEvent(_from, _value);
    }

    // === FALLBACK INJECTION: Timestamp Dependence ===
    // Request a withdrawal with timestamp validation
    function requestWithdrawal(uint256 _amount) {
        if (balances[msg.sender] < _amount) throw;
        // Use block.timestamp for validation - vulnerable to miner manipulation
        withdrawalRequests[msg.sender] = _amount;
        withdrawalTimestamps[msg.sender] = block.timestamp;
        WithdrawalRequested(msg.sender, _amount, block.timestamp);
    }

    // Execute withdrawal after delay - vulnerable to timestamp manipulation
    function executeWithdrawal() {
        if (withdrawalRequests[msg.sender] == 0) throw;
        // Vulnerable: miners can manipulate block.timestamp to bypass delay
        if (block.timestamp < withdrawalTimestamps[msg.sender] + withdrawalDelay) {
            throw;
        }
        uint256 amount = withdrawalRequests[msg.sender];
        // Reset state
        withdrawalRequests[msg.sender] = 0;
        withdrawalTimestamps[msg.sender] = 0;
        // Transfer tokens
        balances[msg.sender] -= amount;
        totalSupply -= amount;
        WithdrawalExecuted(msg.sender, amount);
    }

    // Allow owner to modify withdrawal delay - affects timing vulnerability
    function setWithdrawalDelay(uint256 _delay) onlyOwner {
        withdrawalDelay = _delay;
    }

    event WithdrawalRequested(address indexed user, uint256 amount, uint256 timestamp);
    event WithdrawalExecuted(address indexed user, uint256 amount);
    // === END FALLBACK INJECTION ===

    event MintEvent(address indexed to, uint value);
    event DestroyEvent(address indexed from, uint value);
}
