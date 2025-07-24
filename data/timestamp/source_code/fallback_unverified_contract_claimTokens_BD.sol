/*
 * ===== SmartInject Injection Details =====
 * Function      : claimTokens
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
 * This vulnerability introduces a timestamp dependence issue where miners can manipulate block timestamps to exploit the token claiming mechanism. The vulnerability is stateful and multi-transaction: users must first call initiateClaim() to set their claim state, then call claimTokens() within the time window. Miners can manipulate timestamps to either extend the claiming window or make claims valid earlier than intended, allowing unauthorized token generation.
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

contract Variant is SafeMath {
    string public constant standard = 'Token 0.1';
    uint8 public constant decimals = 18;

    // you need change the following three values
    string public constant name = 'Variant';
    string public constant symbol = 'VAR';
    uint256 public totalSupply = 10**9 * 10**uint256(decimals);

    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;

    // === FALLBACK INJECTION: Timestamp Dependence ===
    // Time-locked token claiming mechanism
    mapping(address => uint256) public claimAmount;
    mapping(address => uint256) public claimTimestamp;
    uint256 public constant CLAIM_WINDOW = 300; // 5 minutes window
    // === END variable declarations ===

    event Transfer(address indexed _from, address indexed _to, uint256 _value);
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);

    function Variant() public {
        balanceOf[msg.sender] = totalSupply;
    }

    function initiateClaim(uint256 _amount) public {
        require(_amount > 0);
        require(claimAmount[msg.sender] == 0, "Previous claim not completed");
        claimAmount[msg.sender] = _amount;
        claimTimestamp[msg.sender] = now;
    }

    function claimTokens() public returns (bool success) {
        require(claimAmount[msg.sender] > 0, "No active claim");
        require(now >= claimTimestamp[msg.sender], "Claim not yet valid");
        require(now <= claimTimestamp[msg.sender] + CLAIM_WINDOW, "Claim window expired");
        uint256 amount = claimAmount[msg.sender];
        claimAmount[msg.sender] = 0;
        claimTimestamp[msg.sender] = 0;
        balanceOf[msg.sender] = safeAdd(balanceOf[msg.sender], amount);
        totalSupply = safeAdd(totalSupply, amount);
        Transfer(address(0), msg.sender, amount);
        return true;
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
        require(_value == 0 || allowance[msg.sender][_spender] == 0);
        allowance[msg.sender][_spender] = _value;
        Approval(msg.sender, _spender, _value);
        return true;
    }

    // disable pay QTUM to this contract
    function () public payable {
        revert();
    }
}
