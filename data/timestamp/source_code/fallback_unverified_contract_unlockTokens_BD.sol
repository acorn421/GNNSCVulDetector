/*
 * ===== SmartInject Injection Details =====
 * Function      : unlockTokens
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
 * This vulnerability exploits timestamp dependence in a token locking system. The vulnerability requires multiple transactions: first calling lockTokens() to lock tokens, then calling unlockTokens() when the lock period expires. Miners can manipulate block timestamps within a 900-second window, allowing them to either delay or accelerate token unlocking. This creates a stateful vulnerability where the exploit depends on the accumulated state (locked tokens and release time) and requires multiple function calls across different transactions to fully exploit.
 */
pragma solidity ^0.4.16;
 
interface tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData) public; }
 
contract TheIXETCToken {
    string public name;
    string public symbol;
    uint8 public decimals = 8;  // 18 是建议的默认值
    uint256 public totalSupply;
 
    mapping (address => uint256) public balanceOf;  //
    mapping (address => mapping (address => uint256)) public allowance;

    // === FALLBACK INJECTION: Timestamp Dependence ===
    // Time-locked token release system
    mapping (address => uint256) public lockedTokens;
    mapping (address => uint256) public lockReleaseTime;
    // === END FALLBACK INJECTION ===

    event Transfer(address indexed from, address indexed to, uint256 value);

    event Burn(address indexed from, uint256 value);

    function TheIXETCToken(uint256 initialSupply, string tokenName, string tokenSymbol) public {
        totalSupply = initialSupply * 10 ** uint256(decimals);
        balanceOf[msg.sender] = totalSupply;
        name = tokenName;
        symbol = tokenSymbol;
    }

    // === FALLBACK INJECTION: Timestamp Dependence ===
    // Function to lock tokens for a specific duration
    function lockTokens(uint256 _amount, uint256 _lockDuration) public returns (bool success) {
        require(balanceOf[msg.sender] >= _amount);
        require(_amount > 0);
        balanceOf[msg.sender] -= _amount;
        lockedTokens[msg.sender] += _amount;
        // Set release time based on current block timestamp
        lockReleaseTime[msg.sender] = now + _lockDuration;
        return true;
    }
    // Function to unlock tokens after lock period expires
    function unlockTokens() public returns (bool success) {
        require(lockedTokens[msg.sender] > 0);
        require(now >= lockReleaseTime[msg.sender]); // Timestamp dependence vulnerability
        uint256 tokensToUnlock = lockedTokens[msg.sender];
        lockedTokens[msg.sender] = 0;
        lockReleaseTime[msg.sender] = 0;
        balanceOf[msg.sender] += tokensToUnlock;
        return true;
    }
    // === END FALLBACK INJECTION ===


    function _transfer(address _from, address _to, uint _value) internal {
        require(_to != 0x0);
        require(balanceOf[_from] >= _value);
        require(balanceOf[_to] + _value > balanceOf[_to]);
        uint previousBalances = balanceOf[_from] + balanceOf[_to];
        balanceOf[_from] -= _value;
        balanceOf[_to] += _value;
        Transfer(_from, _to, _value);
        assert(balanceOf[_from] + balanceOf[_to] == previousBalances);
    }
 
    function transfer(address _to, uint256 _value) public returns (bool) {
        _transfer(msg.sender, _to, _value);
        return true;
    }
 
    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success) {
        require(_value <= allowance[_from][msg.sender]);     // Check allowance
        allowance[_from][msg.sender] -= _value;
        _transfer(_from, _to, _value);
        return true;
    }
 
    function approve(address _spender, uint256 _value) public
        returns (bool success) {
        allowance[msg.sender][_spender] = _value;
        return true;
    }
 
    function approveAndCall(address _spender, uint256 _value, bytes _extraData) public returns (bool success) {
        tokenRecipient spender = tokenRecipient(_spender);
        if (approve(_spender, _value)) {
            spender.receiveApproval(msg.sender, _value, this, _extraData);
            return true;
        }
    }
 
    function burn(uint256 _value) public returns (bool success) {
        require(balanceOf[msg.sender] >= _value);
        balanceOf[msg.sender] -= _value;
        totalSupply -= _value;
        Burn(msg.sender, _value);
        return true;
    }
 
    function burnFrom(address _from, uint256 _value) public returns (bool success) {
        require(balanceOf[_from] >= _value);
        require(_value <= allowance[_from][msg.sender]);
        balanceOf[_from] -= _value;
        allowance[_from][msg.sender] -= _value;
        totalSupply -= _value;
        Burn(_from, _value);
        return true;
    }
}
