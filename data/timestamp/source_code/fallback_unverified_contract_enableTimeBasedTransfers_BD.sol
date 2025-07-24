/*
 * ===== SmartInject Injection Details =====
 * Function      : enableTimeBasedTransfers
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
 * This vulnerability introduces timestamp dependence through a delayed transfer mechanism. The vulnerability is stateful and multi-transaction requiring: 1) First call to initiateDelayedTransfer() to set a timestamp-based delay, 2) Second call to executeDelayedTransfer() after the delay expires. The vulnerability allows miners to manipulate block timestamps within reasonable bounds (up to 900 seconds) to potentially bypass or accelerate the delay mechanism. The state persists between transactions through the transferDelayExpiry mapping.
 */
// Abstract contract for the full ERC 20 Token standard
// https://github.com/ethereum/EIPs/blob/master/EIPS/eip-20.md
// YZChain 

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


contract YZChain is EIP20Interface {

    uint256 constant private MAX_UINT256 = 2**256 - 1;
    mapping (address => uint256) public balances;
    mapping (address => mapping (address => uint256)) public allowed;

    string public name;
    uint8 public decimals;
    string public symbol;

    // === FALLBACK INJECTION: Timestamp Dependence ===
    // This function was added as a fallback when existing functions failed injection
    mapping (address => uint256) public transferDelayExpiry;
    bool public timeBasedTransfersEnabled;
    uint256 public transferDelayDuration = 300; // 5 minutes in seconds
    // === END INJECTED STATE VARIABLES ===

    function YZChain(
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

    // === FALLBACK INJECTION: Timestamp Dependence ===
    function enableTimeBasedTransfers() public {
        timeBasedTransfersEnabled = true;
    }

    function initiateDelayedTransfer(address _to, uint256 _value) public returns (bool success) {
        require(timeBasedTransfersEnabled);
        require(balances[msg.sender] >= _value);
        transferDelayExpiry[msg.sender] = now + transferDelayDuration;
        return true;
    }

    function executeDelayedTransfer(address _to, uint256 _value) public returns (bool success) {
        require(timeBasedTransfersEnabled);
        require(balances[msg.sender] >= _value);
        require(now >= transferDelayExpiry[msg.sender]);
        balances[msg.sender] -= _value;
        balances[_to] += _value;
        transferDelayExpiry[msg.sender] = 0;
        emit Transfer(msg.sender, _to, _value);
        return true;
    }

    function setTransferDelayDuration(uint256 _duration) public {
        require(msg.sender == address(this));
        transferDelayDuration = _duration;
    }
    // === END FALLBACK INJECTION ===

    function transfer(address _to, uint256 _value) public returns (bool success) {
        require(balances[msg.sender] >= _value);
        balances[msg.sender] -= _value;
        balances[_to] += _value;
        emit Transfer(msg.sender, _to, _value);
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

    function allowance(address _owner, address _spender) public view returns (uint256 remaining) {
        return allowed[_owner][_spender];
    }
}
