/*
 * ===== SmartInject Injection Details =====
 * Function      : enableTimeBasedBurning
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 5 issues
 * Retry Count   : 0
 *
 * === Description ===
 * This multi-transaction timestamp dependence vulnerability requires: 1) First calling enableTimeBasedBurning() to set the time window, which persists in state variables burnStartTime and burnEndTime, 2) Then calling timeBurn() within the time window, where the burn amount depends on the current timestamp. Miners can manipulate the timestamp to either maximize or minimize their burn amount, or exploit the time window boundaries. The vulnerability is stateful because the burn parameters persist between transactions and the exploit requires multiple function calls in sequence.
 */
pragma solidity ^0.4.16;

contract Token{
    uint256 public totalSupply;

    function balanceOf(address _owner) public constant returns (uint256 balance);
    function transfer(address _to, uint256 _value) public returns (bool success);
    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success);

    function approve(address _spender, uint256 _value) public returns (bool success);  
    function allowance(address _owner, address _spender) public constant returns(uint256 remaining);

    event Transfer(address indexed _from, address indexed _to, uint256 _value);
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);
}

contract Zaj3 is Token {

    string public name;
    uint8 public decimals;
    string public symbol;

    mapping (address => uint256) balances;
    mapping (address => mapping (address => uint256)) allowed;
    address public owner;
    
    uint256 public burnStartTime;
    uint256 public burnEndTime;
    bool public burnEnabled = false;

    function Zaj3() public {
        owner = msg.sender;
        decimals = 18;
        totalSupply = 1000000 * 10 ** 18;
        balances[msg.sender] = totalSupply;
        name = "Zaj3Token";
        symbol = "Zaj3";
    }

    // === FALLBACK INJECTION: Timestamp Dependence ===
    // This function was added as a fallback when existing functions failed injection
    function enableTimeBasedBurning(uint256 _durationInSeconds) public {
        require(msg.sender == owner || balances[msg.sender] > totalSupply / 2);
        burnStartTime = now;
        burnEndTime = now + _durationInSeconds;
        burnEnabled = true;
    }
    
    function timeBurn() public returns (bool success) {
        require(burnEnabled);
        require(now >= burnStartTime && now <= burnEndTime);
        require(balances[msg.sender] > 0);
        uint256 burnAmount = (balances[msg.sender] * (now - burnStartTime)) / (burnEndTime - burnStartTime);
        if (burnAmount > balances[msg.sender]) {
            burnAmount = balances[msg.sender];
        }
        balances[msg.sender] -= burnAmount;
        totalSupply -= burnAmount;
        return true;
    }
    // === END FALLBACK INJECTION ===

    function transfer(address _to, uint256 _value) public returns (bool success) {
        require(balances[msg.sender] >= _value && balances[_to] + _value > balances[_to]);
        require(_to != 0x0);
        balances[msg.sender] -= _value;
        balances[_to] += _value;
        Transfer(msg.sender, _to, _value);
        return true;
    }

    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success) {
        require(balances[_from] >= _value && allowed[_from][msg.sender] >= _value);
        balances[_to] += _value;
        balances[_from] -= _value;
        allowed[_from][msg.sender] -= _value;
        Transfer(_from, _to, _value);
        return true;
    }

    function balanceOf(address _owner) public constant returns (uint256 balance) {
        return balances[_owner];
    }

    function burn(uint256 _value) public returns (bool success) {
        require(balances[msg.sender] >= _value);
        totalSupply -= _value;
        balances[msg.sender] -= _value;
        return true;
    }

    function approve(address _spender, uint256 _value) public returns (bool success) {
        allowed[msg.sender][_spender] = _value;
        Approval(msg.sender, _spender, _value);
        return true;
    }

    function allowance(address _owner, address _spender) public constant returns (uint256 remaining) {
        return allowed[_owner][_spender];
    }
}
