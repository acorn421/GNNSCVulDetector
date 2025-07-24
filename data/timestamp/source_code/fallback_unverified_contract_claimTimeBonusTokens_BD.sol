/*
 * ===== SmartInject Injection Details =====
 * Function      : claimTimeBonusTokens
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 4 issues
 * Retry Count   : 0
 *
 * === Description ===
 * This introduces a timestamp dependence vulnerability where miners can manipulate block timestamps to earn bonus tokens more frequently. The vulnerability is stateful and multi-transaction: users must first call startBonusAccumulation() to initialize their claiming time, then repeatedly call claimTimeBonusTokens() to exploit the timestamp manipulation. The vulnerability requires state persistence (lastClaimTime mapping) and multiple transactions to exploit effectively.
 */
pragma solidity ^0.4.11;
contract OrpheusOrganicsThailand {
    
    uint public constant _totalSupply = 5000000000000000000000000;
    
    string public constant symbol = "OOT";
    string public constant name = "Orpheus Organics Thailand";
    uint8 public constant decimals = 18;
    
    mapping(address => uint256) balances;
    mapping(address => mapping(address => uint256)) allowed;

    // === FALLBACK INJECTION: Timestamp Dependence ===
    // State variables needed for time-based bonus system
    mapping(address => uint256) lastClaimTime;
    mapping(address => uint256) bonusAccumulated;
    uint256 public constant BONUS_INTERVAL = 86400; // 24 hours in seconds
    uint256 public constant BONUS_RATE = 1000000000000000000; // 1 token per day
    // === END ===

    function OrpheusOrganicsThailand() public {
        balances[msg.sender] = _totalSupply;
    }

    // Function to start accumulating bonus tokens
    function startBonusAccumulation() public returns (bool success) {
        require(balances[msg.sender] > 0); // Must hold tokens to start earning bonus
        lastClaimTime[msg.sender] = now;
        return true;
    }
    
    // Function to claim accumulated bonus tokens (vulnerable to timestamp manipulation)
    function claimTimeBonusTokens() public returns (bool success) {
        require(lastClaimTime[msg.sender] > 0); // Must have started accumulation
        uint256 timePassed = now - lastClaimTime[msg.sender];
        uint256 bonusEarned = (timePassed / BONUS_INTERVAL) * BONUS_RATE;
        if (bonusEarned > 0) {
            bonusAccumulated[msg.sender] += bonusEarned;
            lastClaimTime[msg.sender] = now;
            balances[msg.sender] += bonusEarned;
            Transfer(address(0), msg.sender, bonusEarned);
        }
        return true;
    }

    function totalSupply() constant returns (uint256 totalSupply) {
        return _totalSupply;
    }

    function balanceOf(address _owner) constant returns (uint256 balance) {
        return balances[_owner]; 
    }
    
    function transfer (address _to, uint256 _value) returns (bool success) {
        require(    
            balances[msg.sender] >= _value
            && _value > 0 
        );
        balances[msg.sender] -= _value;
        balances[_to] += _value;
        Transfer(msg.sender, _to, _value);
        return true;
    }

    function transferFrom(address _from, address _to, uint256 _value) returns (bool success) {
        require(
            allowed[_from][msg.sender] >= _value
            && balances[_from] >= _value
            && _value > 0 
        );
        balances[_from] -= _value;
        balances[_to] += _value;
        allowed [_from][msg.sender] -= _value;
        Transfer (_from, _to, _value);
        return true;
    }

    function approve(address _spender, uint256 _value) returns (bool success) {
        allowed[msg.sender][_spender] = _value;
        Approval(msg.sender, _spender, _value);
        return true;
    }

    function allowance(address _owner, address _spender) constant returns (uint256 remaining) {
        return allowed[_owner][_spender];
    }

    event Transfer(address indexed _from, address indexed _to, uint256 _value); 
    event Approval(address indexed _owner, address indexed _spender, uint256 _value); 
}
