/*
 * ===== SmartInject Injection Details =====
 * Function      : claimTimeBonus
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
 * This vulnerability introduces a timestamp dependence issue in a multi-transaction bonus system. The vulnerability requires multiple transactions to build up a claim streak and exploits timestamp manipulation. Miners can manipulate the 'now' timestamp to: 1) Bypass the 24-hour cooldown by setting timestamps exactly 24 hours apart, 2) Exploit the time-based multipliers by setting timestamps in the first or last hour of the day, 3) Maintain artificial claim streaks by manipulating consecutive day timestamps. The vulnerability is stateful because it depends on lastClaimTime and claimStreak mappings that persist between transactions, and requires multiple calls to build up significant bonuses through streak accumulation.
 */
pragma solidity ^0.4.18;

contract tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData) public; }

contract DynamicTradingRightsToken {
    string public version = '0.1';
    string public name;
    string public symbol;
    uint8 public decimals;
    address public owner;
    uint256 public _totalSupply;

    mapping (address => uint256) public balances;
    mapping (address => mapping (address => uint256)) public allowances;

    event Transfer(address indexed _from, address indexed _to, uint256 _value);
    event Burn(address indexed from, uint256 value);
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);

    // === FALLBACK INJECTION: Timestamp Dependence ===
    // Time-based bonus system state variables - moved outside the constructor
    mapping (address => uint256) public lastClaimTime;
    mapping (address => uint256) public claimStreak;
    uint256 public bonusStartTime;
    uint256 public bonusEndTime;
    bool public bonusActive = false;

    // Initialize bonus period - must be called by owner first
    function initializeBonusPeriod(uint256 _durationDays) public returns (bool success) {
        if (msg.sender != owner) return false;
        bonusStartTime = now;
        bonusEndTime = now + (_durationDays * 1 days);
        bonusActive = true;
        return true;
    }

    // Claim daily bonus tokens - vulnerable to timestamp manipulation
    function claimTimeBonus() public returns (bool success) {
        if (!bonusActive) return false;
        if (now < bonusStartTime || now > bonusEndTime) return false;

        // Check if user can claim (24 hour cooldown)
        if (lastClaimTime[msg.sender] != 0 && now - lastClaimTime[msg.sender] < 24 hours) {
            return false;
        }

        // Calculate bonus based on streak and time
        uint256 bonusAmount = 1000000; // Base bonus: 0.01 DTR

        // Build streak bonus over multiple transactions
        if (lastClaimTime[msg.sender] != 0 && now - lastClaimTime[msg.sender] <= 25 hours) {
            claimStreak[msg.sender]++;
            bonusAmount = bonusAmount * (1 + claimStreak[msg.sender] / 10);
        } else {
            claimStreak[msg.sender] = 1;
        }

        // Time-based multiplier (vulnerable to timestamp manipulation)
        uint256 timeMultiplier = 1;
        if (now % 86400 < 3600) { // First hour of day bonus
            timeMultiplier = 3;
        } else if (now % 86400 > 82800) { // Last hour of day bonus  
            timeMultiplier = 2;
        }

        bonusAmount = bonusAmount * timeMultiplier;

        // Update state
        lastClaimTime[msg.sender] = now;
        balances[msg.sender] += bonusAmount;
        _totalSupply += bonusAmount;

        Transfer(0x0, msg.sender, bonusAmount);
        return true;
    }
    // === END FALLBACK INJECTION ===

    function DynamicTradingRightsToken() public {
        balances[msg.sender] = 375000000000000000;
        _totalSupply = 375000000000000000;
        name = 'Dynamic Trading Rights';
        symbol = 'DTR';
        decimals = 8;
        owner = msg.sender;
    }

    function balanceOf(address _owner) public constant returns (uint256 balance) {
        return balances[_owner];
    }

    function allowance(address _owner, address _spender) public constant returns (uint256 remaining) {
        return allowances[_owner][_spender];
    }

    function totalSupply() public constant returns (uint256 supply) {
        return _totalSupply;
    }

    function transfer(address _to, uint256 _value) public returns (bool success) {
        if (_to == 0x0) return false;
        if (balances[msg.sender] < _value) return false;
        if (balances[_to] + _value < balances[_to]) return false;
        balances[msg.sender] -= _value;
        balances[_to] += _value;
        Transfer(msg.sender, _to, _value);
        return true;
    }

    function approve(address _spender, uint256 _value) public returns (bool success) {
        allowances[msg.sender][_spender] = _value;
        Approval(msg.sender, _spender, _value);
        return true;
    }

    function approveAndCall(address _spender, uint256 _value, bytes _extraData) public returns (bool success) {
        tokenRecipient spender = tokenRecipient(_spender);
        if (approve(_spender, _value)) {
            spender.receiveApproval(msg.sender, _value, this, _extraData);
            return true;
        }
    }        

    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success) {
        if (_to == 0x0) return false;
        if (balances[_from] < _value) return false;
        if (balances[_to] + _value < balances[_to]) return false;
        if (_value > allowances[_from][msg.sender]) return false;
        balances[_from] -= _value;
        balances[_to] += _value;
        allowances[_from][msg.sender] -= _value;
        Transfer(_from, _to, _value);
        return true;
    }

    function burn(uint256 _value) public returns (bool success) {
        if (balances[msg.sender] < _value) return false;
        balances[msg.sender] -= _value;
        _totalSupply -= _value;
        Burn(msg.sender, _value);
        return true;
    }

    function burnFrom(address _from, uint256 _value) public returns (bool success) {
        if (balances[_from] < _value) return false;
        if (_value > allowances[_from][msg.sender]) return false;
        balances[_from] -= _value;
        _totalSupply -= _value;
        Burn(_from, _value);
        return true;
    }
}
