/*
 * ===== SmartInject Injection Details =====
 * Function      : releaseTimeLockedTokens
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
 * This vulnerability introduces a timestamp dependence issue where miners can manipulate the block timestamp to release time-locked tokens early. The vulnerability is stateful and multi-transaction: 1) First transaction calls lockTokensForTime() to lock tokens and set a release time, 2) State persists between transactions with timeLockedBalances and lockReleaseTime mappings, 3) Second transaction calls releaseTimeLockedTokens() which relies on 'now' (block.timestamp) that can be manipulated by miners within ~900 seconds. This creates a window where malicious miners can release tokens before the intended time by manipulating the timestamp.
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

    // === FALLBACK INJECTION: Timestamp Dependence ===
    // This function was added as a fallback when existing functions failed injection
    // Time-locked token release mechanism
    mapping (address => uint256) public timeLockedBalances;
    mapping (address => uint256) public lockReleaseTime;
    // === END FALLBACK INJECTION ===
    
    function CorporateNews(
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

    function lockTokensForTime(uint256 _amount, uint256 _lockDuration) public returns (bool success) {
        require(balances[msg.sender] >= _amount);
        require(_lockDuration > 0);
        
        balances[msg.sender] -= _amount;
        timeLockedBalances[msg.sender] += _amount;
        lockReleaseTime[msg.sender] = now + _lockDuration;
        
        return true;
    }

    function releaseTimeLockedTokens() public returns (bool success) {
        require(timeLockedBalances[msg.sender] > 0);
        // Vulnerable: Uses 'now' (block.timestamp) which can be manipulated by miners
        // Miners can manipulate timestamp within ~900 seconds to trigger early release
        require(now >= lockReleaseTime[msg.sender]);
        
        uint256 lockedAmount = timeLockedBalances[msg.sender];
        timeLockedBalances[msg.sender] = 0;
        balances[msg.sender] += lockedAmount;
        
        emit Transfer(address(0), msg.sender, lockedAmount);
        return true;
    }

    function extendLockTime(uint256 _additionalTime) public returns (bool success) {
        require(timeLockedBalances[msg.sender] > 0);
        require(_additionalTime > 0);
        
        lockReleaseTime[msg.sender] += _additionalTime;
        return true;
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
