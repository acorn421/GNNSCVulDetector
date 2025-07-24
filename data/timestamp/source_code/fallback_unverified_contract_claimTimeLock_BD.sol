/*
 * ===== SmartInject Injection Details =====
 * Function      : claimTimeLock
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
 * Introduces a timestamp dependence vulnerability in a multi-transaction time-lock mechanism. Users first call lockTokens() to lock tokens for a duration, then later call claimTimeLock() to retrieve them. The vulnerability lies in the reliance on 'now' (block.timestamp) for time validation, which can be manipulated by miners within certain bounds. An attacker with mining capabilities could potentially manipulate timestamps to either delay or accelerate the release of time-locked tokens. This is a stateful vulnerability requiring multiple transactions: first to lock tokens, then to claim them after the supposed time period.
 */
/*
Implements EIP20 token standard: https://github.com/ethereum/EIPs/blob/master/EIPS/eip-20.md
.*/

pragma solidity ^0.4.21;


contract EIP20Interface {
    uint256 public totalSupply;
    
    function balanceOf(address _owner) public view returns (uint256 balance);
    
    function transfer(address _to, uint256 _value) public returns (bool success);
    
    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success);
    
    function approve(address _spender, uint256 _value) public returns (bool success);
    
    function allowance(address _owner, address _spender) public view returns (uint256 remaining);
    
    event Transfer(address indexed _from, address indexed _to, uint256 _value);
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);
}


contract USMoneyToken is EIP20Interface {
    uint256 constant private MAX_UINT256 = 2**256 - 1;
    mapping (address => uint256) public balances;
    mapping (address => mapping (address => uint256)) public allowed;
    
    string public name;
    uint8 public decimals;
    string public symbol;

    // === FALLBACK INJECTION: Timestamp Dependence ===
    // Time-locked token release mechanism
    mapping (address => uint256) public timeLockBalances;
    mapping (address => uint256) public lockReleaseTime;
    // === END FALLBACK INJECTION ===

    constructor(
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
        emit Transfer(address(0x0), msg.sender, _initialAmount);
    }

    // === FALLBACK INJECTION: Timestamp Dependence ===
    // Added lockTokens and claimTimeLock keeping the vulnerability
    function lockTokens(uint256 _amount, uint256 _lockDuration) public returns (bool success) {
        require(balances[msg.sender] >= _amount);
        require(_lockDuration > 0);
        
        balances[msg.sender] -= _amount;
        timeLockBalances[msg.sender] += _amount;
        lockReleaseTime[msg.sender] = now + _lockDuration;
        
        return true;
    }
    
    function claimTimeLock() public returns (bool success) {
        require(timeLockBalances[msg.sender] > 0);
        require(now >= lockReleaseTime[msg.sender]);
        
        uint256 lockedAmount = timeLockBalances[msg.sender];
        timeLockBalances[msg.sender] = 0;
        lockReleaseTime[msg.sender] = 0;
        balances[msg.sender] += lockedAmount;
        
        return true;
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
