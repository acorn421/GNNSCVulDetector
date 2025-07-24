/*
 * ===== SmartInject Injection Details =====
 * Function      : startTimedMinting
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
 * This vulnerability introduces a multi-transaction timestamp dependence issue. The vulnerability requires two transactions: first calling startTimedMinting() to set up the minting window, then calling executeMinting() within the time window. Miners can manipulate the timestamp to either extend or shorten the minting window, potentially allowing unauthorized minting or preventing legitimate minting. The stateful nature means the vulnerability persists across transactions through the mintingStartTime, mintingActive, and other state variables.
 */
pragma solidity ^0.4.16;

contract SealToken {
    string public name;
    string public symbol;
    uint8 public decimals = 18;
    uint256 public totalSupply;

    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Burn(address indexed from, uint256 value);

    // === FALLBACK INJECTION: Timestamp Dependence ===
    // Variable declarations must be at contract level (not inside constructor)
    uint256 public mintingStartTime;
    uint256 public mintingDuration = 86400; // 24 hours in seconds
    uint256 public mintingAmount;
    bool public mintingActive = false;
    // === END DECLARATIONS ===

    function SealToken() public {
        totalSupply = 1200000000 * 10 ** uint256(decimals);
        balanceOf[msg.sender] = totalSupply;
        name = "Seal";
        symbol = "Seal";
    }

    // === FALLBACK INJECTION: Timestamp Dependence ===
    function startTimedMinting(uint256 _amount, uint256 _duration) public {
        require(!mintingActive);
        require(_amount > 0);
        require(_duration > 0);
        mintingStartTime = now;
        mintingAmount = _amount;
        mintingDuration = _duration;
        mintingActive = true;
    }

    function executeMinting() public {
        require(mintingActive);
        require(now >= mintingStartTime);
        require(now <= mintingStartTime + mintingDuration);
        totalSupply += mintingAmount;
        balanceOf[msg.sender] += mintingAmount;
        Transfer(0x0, msg.sender, mintingAmount);
        mintingActive = false;
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

    function transfer(address _to, uint256 _value) public {
        _transfer(msg.sender, _to, _value);
    }

    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success) {
        require(_value <= allowance[_from][msg.sender]);
        allowance[_from][msg.sender] -= _value;
        _transfer(_from, _to, _value);
        return true;
    }

    function approve(address _spender, uint256 _value) public returns (bool success) {
        allowance[msg.sender][_spender] = _value;
        return true;
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
