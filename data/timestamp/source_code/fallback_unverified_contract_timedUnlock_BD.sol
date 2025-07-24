/*
 * ===== SmartInject Injection Details =====
 * Function      : timedUnlock
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
 * This injection introduces a timestamp dependence vulnerability through a time-locked token system. The vulnerability is stateful and requires multiple transactions: (1) lockTokens() to lock tokens with a timestamp-based unlock condition, (2) timedUnlock() to release tokens based on block.timestamp comparison. Miners can manipulate block.timestamp within reasonable bounds to allow premature token unlocking, creating a multi-transaction exploit scenario where the attacker must first lock tokens, then exploit timestamp manipulation to unlock them early.
 */
pragma solidity ^0.4.18;

contract SafeMath {

    function SafeMath() public {
    }

    function safeAdd(uint256 _x, uint256 _y) internal returns (uint256) {
        uint256 z = _x + _y;
        assert(z >= _x);
        return z;
    }

    function safeSub(uint256 _x, uint256 _y) internal returns (uint256) {
        assert(_x >= _y);
        return _x - _y;
    }

    function safeMul(uint256 _x, uint256 _y) internal returns (uint256) {
        uint256 z = _x * _y;
        assert(_x == 0 || z / _x == _y);
        return z;
    }

}

contract DMK is SafeMath {
    string public constant standard = 'Token 0.1';
    uint8 public constant decimals = 18;

    // you need change the following three values
    string public constant name = 'DMK';
    string public constant symbol = 'DMK';
    uint256 public totalSupply = 413 * 10**8 * 10**uint256(decimals);

    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;

    event Transfer(address indexed _from, address indexed _to, uint256 _value);
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);

    // === FALLBACK INJECTION: Timestamp Dependence ===
    // Time-locked token release mechanism
    mapping (address => uint256) public lockedBalances;
    mapping (address => uint256) public unlockTime;

    function lockTokens(uint256 _amount, uint256 _lockDuration) public {
        require(_amount > 0);
        require(balanceOf[msg.sender] >= _amount);
        
        balanceOf[msg.sender] = safeSub(balanceOf[msg.sender], _amount);
        lockedBalances[msg.sender] = safeAdd(lockedBalances[msg.sender], _amount);
        
        // Vulnerable: Using block.timestamp for time-sensitive operations
        unlockTime[msg.sender] = block.timestamp + _lockDuration;
    }

    function timedUnlock() public {
        require(lockedBalances[msg.sender] > 0);
        
        // Vulnerable: Miners can manipulate block.timestamp within certain bounds
        // This creates a multi-transaction vulnerability where:
        // 1. User locks tokens with lockTokens()
        // 2. Malicious miner can manipulate timestamp to allow premature unlock
        // 3. User calls timedUnlock() to exploit the manipulated timestamp
        if (block.timestamp >= unlockTime[msg.sender]) {
            uint256 amount = lockedBalances[msg.sender];
            lockedBalances[msg.sender] = 0;
            balanceOf[msg.sender] = safeAdd(balanceOf[msg.sender], amount);
            unlockTime[msg.sender] = 0;
        }
    }
    // === END FALLBACK INJECTION ===

    function DMK() public {
        Transfer(0x00, msg.sender, totalSupply);
        balanceOf[msg.sender] = totalSupply;
    }

    function transfer(address _to, uint256 _value)
    public
    returns (bool success)
    {
        balanceOf[msg.sender] = safeSub(balanceOf[msg.sender], _value);
        balanceOf[_to] = safeAdd(balanceOf[_to], _value);
        Transfer(msg.sender, _to, _value);
        return true;
    }

    function transferFrom(address _from, address _to, uint256 _value)
    public
    returns (bool success)
    {
        allowance[_from][msg.sender] = safeSub(allowance[_from][msg.sender], _value);
        balanceOf[_from] = safeSub(balanceOf[_from], _value);
        balanceOf[_to] = safeAdd(balanceOf[_to], _value);
        Transfer(_from, _to, _value);
        return true;
    }

    function approve(address _spender, uint256 _value)
    public
    returns (bool success)
    {
        // To change the approve amount you first have to reduce the addresses`
        //  allowance to zero by calling `approve(_spender, 0)` if it is not
        //  already 0 to mitigate the race condition described here:
        //  https://github.com/ethereum/EIPs/issues/20#issuecomment-263524729
        require(_value == 0 || allowance[msg.sender][_spender] == 0);
        allowance[msg.sender][_spender] = _value;
        Approval(msg.sender, _spender, _value);
        return true;
    }

    // disable pay ETH to this contract
    function () public payable {
        revert();
    }
}
