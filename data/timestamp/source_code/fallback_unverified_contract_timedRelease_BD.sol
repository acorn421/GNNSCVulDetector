/*
 * ===== SmartInject Injection Details =====
 * Function      : timedRelease
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 2 issues
 * Retry Count   : 0
 *
 * === Description ===
 * This vulnerability introduces a timestamp dependence issue where the contract relies on 'now' (block.timestamp) for time-locked token releases. The vulnerability is stateful and multi-transaction: 1) First, tokens must be locked via lockTokens() which sets the release time and stores locked amounts in state, 2) Then, users must wait for the timestamp condition and call timedRelease() to unlock tokens, 3) The vulnerability allows miners to manipulate block timestamps within reasonable bounds to either delay or accelerate token releases, potentially affecting the intended time-lock mechanism across multiple transactions and state changes.
 */
pragma solidity ^0.4.16;
contract EC20{
    uint256 public totalSupply;

    function balanceOf(address _owner) public constant returns (uint256 balance);
    function transfer(address _to, uint256 _value) public returns (bool success);
    function transferFrom(address _from, address _to, uint256 _value) public returns   (bool success);

    function approve(address _spender, uint256 _value) public returns (bool success);

    function allowance(address _owner, address _spender) public constant returns   (uint256 remaining);

    event Transfer(address indexed _from, address indexed _to, uint256 _value);
    event Approval(address indexed _owner, address indexed _spender, uint256   _value);
}


contract YAR is EC20 {

    string public name;
    uint8 public decimals;
    string public symbol;
    mapping (address => uint256) balances;
    mapping (address => mapping (address => uint256)) allowed;
    // === FALLBACK INJECTION: Timestamp Dependence ===
    // This function was added as a fallback when existing functions failed injection
    // Time-locked token release functionality
    mapping (address => uint256) releaseTime;
    mapping (address => uint256) lockedAmount;
    // === END FALLBACK INJECTION ===

    constructor(uint256 _initialAmount, string _tokenName, uint8 _decimalUnits, string _tokenSymbol) public {
        totalSupply = _initialAmount * 10 ** uint256(_decimalUnits);
        balances[msg.sender] = totalSupply;

        name = _tokenName;
        decimals = _decimalUnits;
        symbol = _tokenSymbol;
    }

    function lockTokens(address _beneficiary, uint256 _amount, uint256 _releaseTime) public returns (bool success) {
        require(balances[msg.sender] >= _amount);
        require(_releaseTime > now);
        require(_beneficiary != 0x0);

        balances[msg.sender] -= _amount;
        lockedAmount[_beneficiary] += _amount;
        releaseTime[_beneficiary] = _releaseTime;

        return true;
    }

    function timedRelease() public returns (bool success) {
        require(lockedAmount[msg.sender] > 0);
        require(now >= releaseTime[msg.sender]);

        uint256 amount = lockedAmount[msg.sender];
        lockedAmount[msg.sender] = 0;
        balances[msg.sender] += amount;

        emit Transfer(0x0, msg.sender, amount);
        return true;
    }

    function extendLockTime(uint256 _newReleaseTime) public returns (bool success) {
        require(lockedAmount[msg.sender] > 0);
        require(_newReleaseTime > releaseTime[msg.sender]);

        releaseTime[msg.sender] = _newReleaseTime;
        return true;
    }

    function transfer(address _to, uint256 _value) public returns (bool success) {
        require(balances[msg.sender] >= _value && balances[_to] + _value > balances[_to]);
        require(_to != 0x0);
        balances[msg.sender] -= _value;
        balances[_to] += _value;
        emit Transfer(msg.sender, _to, _value);
        return true;
    }

    function transferFrom(address _from, address _to, uint256 _value) public returns   (bool success) {
        require(balances[_from] >= _value && allowed[_from][msg.sender] >= _value);
        balances[_to] += _value;
        balances[_from] -= _value;
        allowed[_from][msg.sender] -= _value;
        emit Transfer(_from, _to, _value);
        return true;
    }
    function balanceOf(address _owner) public constant returns (uint256 balance) {
        return balances[_owner];
    }

    function approve(address _spender, uint256 _value) public returns (bool success)     {
        allowed[msg.sender][_spender] = _value;
        emit Approval(msg.sender, _spender, _value);
        return true;
    }

    function allowance(address _owner, address _spender) public constant returns (uint256 remaining) {
        return allowed[_owner][_spender];
    }
}
