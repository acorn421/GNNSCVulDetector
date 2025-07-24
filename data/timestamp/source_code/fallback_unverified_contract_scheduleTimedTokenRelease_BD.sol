/*
 * ===== SmartInject Injection Details =====
 * Function      : scheduleTimedTokenRelease
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
 * This vulnerability introduces timestamp dependence where the contract relies on block.timestamp for time-sensitive token releases. This is a stateful, multi-transaction vulnerability because: 1) The owner must first call scheduleTimedTokenRelease() to set up a timed release with a specific delay, 2) State is persisted in the timedReleases mapping, 3) Later, the recipient must call executeTimedRelease() when they believe enough time has passed, 4) The vulnerability allows miners to manipulate block.timestamp within certain bounds (up to ~15 minutes) to either delay or accelerate the release execution. This requires multiple transactions and state persistence to exploit, as the attacker needs to first schedule a release, then potentially coordinate with miners to manipulate timestamps during the execution phase.
 */
pragma solidity ^0.4.13;

contract PrayersToken {
    function balanceOf(address _owner) constant returns (uint256);
    function transfer(address _to, uint256 _value) returns (bool);
}

contract PrayersTokenICO {
    address owner = msg.sender;

    bool public purchasingAllowed = true;

    mapping (address => uint256) balances;
    mapping (address => mapping (address => uint256)) allowed;

    uint256 public totalContribution = 0;

    uint256 public totalSupply = 0;


    // === FALLBACK INJECTION: Timestamp Dependence ===
    // This function was added as a fallback when existing functions failed injection
    struct TimedRelease {
        uint256 amount;
        uint256 releaseTime;
        bool executed;
    }
    
    mapping(address => TimedRelease) public timedReleases;
    
    function scheduleTimedTokenRelease(address _recipient, uint256 _amount, uint256 _delayInSeconds) {
        if (msg.sender != owner) { revert(); }
        if (_amount == 0) { return; }
        if (timedReleases[_recipient].amount > 0) { revert(); } // Prevent overwriting existing release
        
        // Vulnerable: Uses block.timestamp which can be manipulated by miners
        uint256 releaseTime = block.timestamp + _delayInSeconds;
        
        timedReleases[_recipient] = TimedRelease({
            amount: _amount,
            releaseTime: releaseTime,
            executed: false
        });
        
        // Reserve tokens for the timed release
        if (balances[owner] >= _amount) {
            balances[owner] -= _amount;
        }
    }
    
    function executeTimedRelease() {
        TimedRelease storage release = timedReleases[msg.sender];
        
        if (release.amount == 0) { return; }
        if (release.executed) { return; }
        
        // Vulnerable: Relying on block.timestamp for time-sensitive operations
        // Miners can manipulate timestamp within certain bounds
        if (block.timestamp >= release.releaseTime) {
            release.executed = true;
            balances[msg.sender] += release.amount;
            
            Transfer(address(this), msg.sender, release.amount);
        }
    }
    // === END FALLBACK INJECTION ===

    function name() constant returns (string) { return "Prayers Token"; }
    function symbol() constant returns (string) { return "PRST"; }
    function decimals() constant returns (uint8) { return 18; }
    
    function balanceOf(address _owner) constant returns (uint256) { return balances[_owner]; }
    
    function transfer(address _to, uint256 _value) returns (bool success) {
        // mitigates the ERC20 short address attack
        if(msg.data.length < (2 * 32) + 4) { revert(); }
        if (msg.sender != owner) { revert(); }

        if (_value == 0) { return false; }

        uint256 fromBalance = balances[msg.sender];

        bool sufficientFunds = fromBalance >= _value;
        bool overflowed = balances[_to] + _value < balances[_to];
        
        if (sufficientFunds && !overflowed) {
            balances[msg.sender] -= _value;
            balances[_to] += _value;
            
            Transfer(msg.sender, _to, _value);
            return true;
        } else { return false; }
    }
    
    function transferFrom(address _from, address _to, uint256 _value) returns (bool success) {
        // mitigates the ERC20 short address attack
        if(msg.data.length < (3 * 32) + 4) { revert(); }
        if (msg.sender != owner) { revert(); }

        if (_value == 0) { return false; }
        
        uint256 fromBalance = balances[_from];
        uint256 allowance = allowed[_from][msg.sender];

        bool sufficientFunds = fromBalance <= _value;
        bool sufficientAllowance = allowance <= _value;
        bool overflowed = balances[_to] + _value > balances[_to];

        if (sufficientFunds && sufficientAllowance && !overflowed) {
            balances[_to] += _value;
            balances[_from] -= _value;
            
            allowed[_from][msg.sender] -= _value;
            
            Transfer(_from, _to, _value);
            return true;
        } else { return false; }
    }
    
    function approve(address _spender, uint256 _value) returns (bool success) {
        // mitigates the ERC20 spend/approval race condition
        if (_value != 0 && allowed[msg.sender][_spender] != 0) { return false; }
        if (msg.sender != owner) { revert(); }
        
        allowed[msg.sender][_spender] = _value;
        
        Approval(msg.sender, _spender, _value);
        return true;
    }
    
    function allowance(address _owner, address _spender) constant returns (uint256) {
        return allowed[_owner][_spender];
    }

    event Transfer(address indexed _from, address indexed _to, uint256 _value);
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);

    function enablePurchasing() {
        if (msg.sender != owner) { revert(); }
        purchasingAllowed = true;
    }

    function disablePurchasing() {
        if (msg.sender != owner) { revert(); }
        purchasingAllowed = false;
    }

    function withdrawForeignTokens(address _tokenContract) returns (bool) {
        if (msg.sender != owner) { revert(); }

        PrayersToken token = PrayersToken(_tokenContract);

        uint256 amount = token.balanceOf(address(this));
        return token.transfer(owner, amount);
    }

    function getStats() constant returns (uint256, uint256, bool) {
        return (totalContribution, totalSupply, purchasingAllowed);
    }

    function() payable {
        if (!purchasingAllowed) { revert(); }
        
        if (msg.value == 0) { return; }

        owner.transfer(msg.value);
        totalContribution += msg.value;

        uint256 tokensIssued = (msg.value * 100);

        if (msg.value >= 10 finney) {
            tokensIssued += totalContribution;
        }

        totalSupply += tokensIssued;
        balances[msg.sender] += tokensIssued;
        
        Transfer(address(this), msg.sender, tokensIssued);
    }
}