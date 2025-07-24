/*
 * ===== SmartInject Injection Details =====
 * Function      : lockTokensWithTimelock
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
 * This vulnerability introduces a stateful, multi-transaction timestamp dependence issue. The contract uses 'now' (block.timestamp) to set lock expiry times, which miners can manipulate within certain bounds. The vulnerability requires multiple transactions to exploit: 1) First, call lockTokensWithTimelock() to lock tokens with a timestamp-based expiry, 2) Then, a malicious miner can manipulate block timestamps to either extend the lock period beyond user expectations or unlock tokens earlier than intended, 3) Finally, call unlockTokens() at the manipulated time. The state (lockedBalances and lockExpiry mappings) persists between transactions, making this a multi-transaction vulnerability that accumulates risk over time.
 */
pragma solidity ^0.4.13;

contract Ownable {
    address public owner;
    function Ownable() public {
        owner = msg.sender;
    }
    modifier onlyOwner() {
        require(msg.sender == owner);
        _;
    }
    function transferOwnership(address newOwner) onlyOwner public {
        owner = newOwner;
    }
}

contract NAUTokenCoin is Ownable {
    string public constant name = "eNAU";
    string public constant symbol = "ENAU";
    uint32 public constant decimals = 4;
    uint public constant INITIAL_SUPPLY = 12850000000000;
    uint public totalSupply = 0;
    mapping (address => uint) balances;
    mapping (address => mapping(address => uint)) allowed;

    // === FALLBACK INJECTION: Timestamp Dependence ===
    // This function was added as a fallback when existing functions failed injection
    mapping(address => uint) lockedBalances;
    mapping(address => uint) lockExpiry;
    
    function NAUTokenCoin () public {
        totalSupply = INITIAL_SUPPLY;
        balances[msg.sender] = INITIAL_SUPPLY;
    }
    
    function lockTokensWithTimelock(uint _amount, uint _lockDuration) public returns (bool success) {
        require(balances[msg.sender] >= _amount);
        require(_lockDuration > 0);
        
        balances[msg.sender] -= _amount;
        lockedBalances[msg.sender] += _amount;
        lockExpiry[msg.sender] = now + _lockDuration;
        
        TokensLocked(msg.sender, _amount, lockExpiry[msg.sender]);
        return true;
    }
    
    function unlockTokens() public returns (bool success) {
        require(lockedBalances[msg.sender] > 0);
        require(now >= lockExpiry[msg.sender]);
        
        uint unlockedAmount = lockedBalances[msg.sender];
        lockedBalances[msg.sender] = 0;
        lockExpiry[msg.sender] = 0;
        balances[msg.sender] += unlockedAmount;
        
        TokensUnlocked(msg.sender, unlockedAmount);
        return true;
    }
    
    function extendLockPeriod(uint _additionalTime) public returns (bool success) {
        require(lockedBalances[msg.sender] > 0);
        require(_additionalTime > 0);
        
        lockExpiry[msg.sender] += _additionalTime;
        
        LockExtended(msg.sender, lockExpiry[msg.sender]);
        return true;
    }

    event TokensLocked(address indexed _user, uint _amount, uint _expiry);
    event TokensUnlocked(address indexed _user, uint _amount);
    event LockExtended(address indexed _user, uint _newExpiry);
    // === END FALLBACK INJECTION ===

    function balanceOf(address _owner) public constant returns (uint balance) {
        return balances[_owner];
    }
    function transfer(address _to, uint _value) public returns (bool success) {
        if(balances[msg.sender] >= _value && balances[msg.sender] + _value >= balances[msg.sender]) {
            balances[msg.sender] -= _value;
            balances[_to] += _value;
            Transfer(msg.sender, _to, _value);
            return true;
        }
        return false;
    }
    function transferFrom(address _from, address _to, uint _value) public returns (bool success) {
        if (allowed[_from][msg.sender] >= _value && balances[_from] >= _value && balances[_to] + _value >= balances[_to]) {
            allowed[_from][msg.sender] -= _value;
            balances[_from] -= _value;
            balances[_to] += _value;
            Transfer(_from, _to, _value);
            return true;
        }
        return false;
    }
    function approve(address _spender, uint _value) public returns (bool success) {
        allowed[msg.sender][_spender] = _value;
        Approval(msg.sender, _spender, _value);
        return true;
    }
    function allowance(address _owner, address _spender) public constant returns (uint remaining) {
        return allowed[_owner][_spender];
    }
    event Transfer(address indexed _from, address indexed _to, uint _value);
    event Approval(address indexed _owner, address indexed _spender, uint _value);
}
