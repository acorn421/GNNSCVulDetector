/*
 * ===== SmartInject Injection Details =====
 * Function      : lockTokensWithTimestamp
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
 * This vulnerability introduces timestamp dependence through a token locking mechanism. The vulnerability is stateful and multi-transaction because: 1) Users must first call lockTokensWithTimestamp() to lock tokens with a timestamp, 2) The state persists between transactions with lockedTokens and lockTimestamp mappings, 3) Users must wait for the lock period and then call unlockTokens() in a separate transaction. Miners can manipulate the 'now' timestamp (block.timestamp) to either prevent unlocking by setting timestamps in the past, or allow early unlocking by setting future timestamps. This requires multiple transactions to exploit - first observing locked tokens, then mining blocks with manipulated timestamps to affect the unlock timing.
 */
pragma solidity ^0.4.9;
library SafeMath {
    function mul(uint256 a, uint256 b) internal constant returns(uint256) {
        uint256 c = a * b;
        assert(a == 0 || c / a == b);
        return c;
    }

    function div(uint256 a, uint256 b) internal constant returns(uint256) {
        uint256 c = a / b;
        return c;
    }

    function sub(uint256 a, uint256 b) internal constant returns(uint256) {
        assert(b <= a);
        return a - b;
    }

    function add(uint256 a, uint256 b) internal constant returns(uint256) {
        uint256 c = a + b;
        assert(c >= a);
        return c;
    }
}
contract MoneroGold {
    using SafeMath for uint256;
    mapping(address => mapping(address => uint256)) allowed;
    mapping(address => uint256) balances;
    uint256 public totalSupply;
    uint256 public decimals;
    address public owner;
    bytes32 public name;
    bytes32 public symbol;
    bool public fullSupplyUnlocked;
    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed _owner, address indexed spender, uint256 value);

    // === FALLBACK INJECTION: Timestamp Dependence ===
    // State variables for time-locked tokens
    mapping(address => uint256) lockedTokens;
    mapping(address => uint256) lockTimestamp;
    uint256 public lockDuration = 86400; // 24 hours in seconds
    // === END FALLBACK INJECTION ===

    function MoneroGold() {
        totalSupply = 21000000;
        name = 'MoneroGold';
        symbol = 'XMRG';
        owner = 0x16aa7328A402CBbe46afdbA9FF2b54cb1a0124B6;
        balances[owner] = 21000000;
        decimals = 0;
    }

    // === FALLBACK INJECTION: Timestamp Dependence ===
    // Function to lock tokens with timestamp dependency
    function lockTokensWithTimestamp(uint256 _amount) returns(bool) {
        require(_amount > 0);
        require(balances[msg.sender] >= _amount);
        // Transfer tokens to locked balance
        balances[msg.sender] = balances[msg.sender].sub(_amount);
        lockedTokens[msg.sender] = lockedTokens[msg.sender].add(_amount);
        // Set lock timestamp - vulnerable to miner manipulation
        lockTimestamp[msg.sender] = now;
        return true;
    }
    // Function to unlock tokens - requires timestamp validation
    function unlockTokens() returns(bool) {
        require(lockedTokens[msg.sender] > 0);
        // Vulnerable timestamp check - miners can manipulate 'now'
        require(now >= lockTimestamp[msg.sender].add(lockDuration));
        uint256 amount = lockedTokens[msg.sender];
        lockedTokens[msg.sender] = 0;
        lockTimestamp[msg.sender] = 0;
        // Return tokens to regular balance
        balances[msg.sender] = balances[msg.sender].add(amount);
        return true;
    }
    // Function to check if tokens can be unlocked - also timestamp dependent
    function canUnlockTokens(address _owner) constant returns(bool) {
        if (lockedTokens[_owner] == 0) return false;
        return now >= lockTimestamp[_owner].add(lockDuration);
    }
    // === END FALLBACK INJECTION ===

    function unlockSupply() returns(bool)
    {
        require(msg.sender == owner);
        require(!fullSupplyUnlocked);
        balances[owner] = balances[owner].add(21000000);
        fullSupplyUnlocked = true;
        return true;
    }
    function balanceOf(address _owner) constant returns(uint256 balance)
    {
        return balances[_owner];
    }

    function allowance(address _owner, address _spender) constant returns(uint256 remaining)
    {
        return allowed[_owner][_spender];
    }

    function transfer(address _to, uint256 _value) returns(bool)
    {
        balances[msg.sender] = balances[msg.sender].sub(_value);
        balances[_to] = balances[_to].add(_value);
        Transfer(msg.sender, _to, _value);
        return true;
    }

    function transferFrom(address _from, address _to, uint256 _value) returns(bool) 
    {
        var _allowance = allowed[_from][msg.sender];
        balances[_to] = balances[_to].add(_value);
        balances[_from] = balances[_from].sub(_value);
        allowed[_from][msg.sender] = _allowance.sub(_value);
        Transfer(_from, _to, _value);
        return true;
    }

    function approve(address _spender, uint256 _value) returns(bool) 
    {
        require((_value == 0) || (allowed[msg.sender][_spender] == 0));
        allowed[msg.sender][_spender] = _value;
        Approval(msg.sender, _spender, _value);
        return true;
    }

    function() {
        revert();
    }
}
