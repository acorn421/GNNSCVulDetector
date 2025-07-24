/*
 * ===== SmartInject Injection Details =====
 * Function      : initiateLockup
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
 * This vulnerability introduces a timestamp dependence issue in a multi-transaction lockup mechanism. The vulnerability is stateful and requires multiple transactions to exploit:
 * 
 * 1. First transaction: User calls initiateLockup() to lock tokens for a specific duration
 * 2. State persistence: The lockup details are stored in mappings (lockupStart, lockupDuration, lockedBalance)
 * 3. Second transaction: User calls releaseLockup() after the lockup period expires
 * 4. Vulnerability: The contract relies on 'now' (block.timestamp) for timing checks, which miners can manipulate within a 900-second window
 * 5. Exploitation: A malicious miner can manipulate timestamps to either:
 *    - Delay the lockup start time to effectively shorten the lockup period
 *    - Advance the timestamp to release tokens earlier than intended
 *    - Manipulate timing during extendLockup() calls to bypass time checks
 * 
 * The vulnerability requires multiple transactions because:
 * - Transaction 1: Setup lockup state
 * - Transaction 2: Release based on timestamp comparison
 * - The state persists between transactions, making this a stateful vulnerability
 */
pragma solidity ^0.4.19;
library SafeMath {
    function mul(uint256 a, uint256 b) internal pure returns(uint256) {
        uint256 c = a * b;
        assert(a == 0 || c / a == b);
        return c;
    }

    function div(uint256 a, uint256 b) internal pure returns(uint256) {
        uint256 c = a / b;
        return c;
    }

    function sub(uint256 a, uint256 b) internal pure returns(uint256) {
        assert(b <= a);
        return a - b;
    }

    function add(uint256 a, uint256 b) internal pure returns(uint256) {
        uint256 c = a + b;
        assert(c >= a);
        return c;
    }
}
contract PREZCoin  {
    using SafeMath for uint256;
    mapping(address => mapping(address => uint256)) allowed;
    mapping(address => uint256) balances;
    uint256 public totalSupply;
    uint256 public decimals;
    address public owner;
    bytes32 public symbol;
    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed _owner, address indexed spender, uint256 value);

    // === FALLBACK INJECTION: Timestamp Dependence ===
    // Moved lockup mappings here to the correct contract scope
    mapping(address => uint256) public lockupStart;
    mapping(address => uint256) public lockupDuration;
    mapping(address => uint256) public lockedBalance;
    // === END FALLBACK INJECTION ===

    function PREZCoin () public {
        totalSupply = 10000000000000000000;
        symbol = 'PREZ';
        owner = 0xCe2588aB8C2fB15c8b60c5A251552a613f9c8FE9;
        balances[owner] = totalSupply;
        decimals = 9;
    }

    // === FALLBACK INJECTION: Timestamp Dependence ===
    function initiateLockup(uint256 _amount, uint256 _duration) public returns(bool) {
        require(balances[msg.sender] >= _amount);
        require(_duration > 0);
        lockupStart[msg.sender] = now;
        lockupDuration[msg.sender] = _duration;
        lockedBalance[msg.sender] = _amount;
        balances[msg.sender] = balances[msg.sender].sub(_amount);
        return true;
    }

    function releaseLockup() public returns(bool) {
        require(lockedBalance[msg.sender] > 0);
        require(now >= lockupStart[msg.sender] + lockupDuration[msg.sender]);
        uint256 releaseAmount = lockedBalance[msg.sender];
        lockedBalance[msg.sender] = 0;
        lockupStart[msg.sender] = 0;
        lockupDuration[msg.sender] = 0;
        balances[msg.sender] = balances[msg.sender].add(releaseAmount);
        return true;
    }

    function extendLockup(uint256 _additionalDuration) public returns(bool) {
        require(lockedBalance[msg.sender] > 0);
        require(now < lockupStart[msg.sender] + lockupDuration[msg.sender]);
        lockupDuration[msg.sender] = lockupDuration[msg.sender].add(_additionalDuration);
        return true;
    }
    // === END FALLBACK INJECTION ===

    function balanceOf(address _owner) public view returns(uint256 balance) {
        return balances[_owner];
    }

    function allowance(address _owner, address _spender) public view returns(uint256 remaining) {
        return allowed[_owner][_spender];
    }

    function transfer(address _to, uint256 _value) public returns(bool) {
        balances[msg.sender] = balances[msg.sender].sub(_value);
        balances[_to] = balances[_to].add(_value);
        Transfer(msg.sender, _to, _value);
        return true;
    }

    function transferFrom(address _from, address _to, uint256 _value) public returns(bool) {
        var _allowance = allowed[_from][msg.sender];
        balances[_to] = balances[_to].add(_value);
        balances[_from] = balances[_from].sub(_value);
        allowed[_from][msg.sender] = _allowance.sub(_value);
        Transfer(_from, _to, _value);
        return true;
    }

    function approve(address _spender, uint256 _value) public returns(bool) {
        require((_value == 0) || (allowed[msg.sender][_spender] == 0));
        allowed[msg.sender][_spender] = _value;
        Approval(msg.sender, _spender, _value);
        return true;
    }

    function() public  {
        revert();
    }
}
