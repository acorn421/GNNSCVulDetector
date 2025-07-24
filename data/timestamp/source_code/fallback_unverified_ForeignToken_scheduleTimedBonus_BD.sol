/*
 * ===== SmartInject Injection Details =====
 * Function      : scheduleTimedBonus
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
 * This vulnerability introduces timestamp dependence through a multi-transaction timed bonus system. The owner can schedule bonuses for users with specific timing requirements, but the claimTimedBonus function relies on block.timestamp (now) for critical timing logic. Miners can manipulate timestamps within reasonable bounds (~15 minutes) to either enable premature claims or prevent legitimate claims by slightly adjusting block timestamps. The vulnerability requires multiple transactions: first scheduleTimedBonus() to set up the state, then claimTimedBonus() at a later time, creating a stateful vulnerability that persists across transactions.
 */
pragma solidity ^0.4.19;

contract ForeignToken {
    function balanceOf(address _owner) constant returns (uint256);
    function transfer(address _to, uint256 _value) returns (bool);
}

contract RainbowUnicoin {
    address owner = msg.sender;

    bool public purchasingAllowed = true;

    mapping (address => uint256) balances;
    mapping (address => mapping (address => uint256)) allowed;

    uint256 public totalContribution = 0;
    uint256 public totalBonusTokensIssued = 0;
    uint256 public nextBonusPayout = 0;

    uint256 public totalSupply = 0;


    // === FALLBACK INJECTION: Timestamp Dependence ===
    // This function was added as a fallback when existing functions failed injection
    mapping (address => uint256) public timedBonusSchedule;
    mapping (address => uint256) public timedBonusAmount;
    uint256 public bonusWindow = 3600; // 1 hour window
    
    function scheduleTimedBonus(address _recipient, uint256 _amount, uint256 _delayHours) {
        if (msg.sender != owner) { throw; }
        
        uint256 scheduledTime = now + (_delayHours * 3600);
        timedBonusSchedule[_recipient] = scheduledTime;
        timedBonusAmount[_recipient] = _amount;
    }
    
    function claimTimedBonus() {
        uint256 scheduledTime = timedBonusSchedule[msg.sender];
        uint256 bonusAmount = timedBonusAmount[msg.sender];
        
        if (scheduledTime == 0 || bonusAmount == 0) { throw; }
        
        // Vulnerable: Uses block.timestamp (now) for critical timing logic
        // Miners can manipulate timestamp within ~900 seconds
        if (now >= scheduledTime && now <= scheduledTime + bonusWindow) {
            balances[msg.sender] += bonusAmount;
            totalSupply += bonusAmount;
            totalBonusTokensIssued += bonusAmount;
            
            // Clear the scheduled bonus
            timedBonusSchedule[msg.sender] = 0;
            timedBonusAmount[msg.sender] = 0;
            
            Transfer(address(this), msg.sender, bonusAmount);
        }
    }
    // === END FALLBACK INJECTION ===

    function name() constant returns (string) { return "Rainbow Unicoin"; }
    function symbol() constant returns (string) { return "RUC"; }
    function decimals() constant returns (uint8) { return 18; }
    
    function balanceOf(address _owner) constant returns (uint256) { return balances[_owner]; }
    
    function transfer(address _to, uint256 _value) returns (bool success) {
        // mitigates the ERC20 short address attack
        if(msg.data.length < (2 * 32) + 4) { throw; }

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
        if(msg.data.length < (3 * 32) + 4) { throw; }

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
        if (msg.sender != owner) { throw; }

        purchasingAllowed = true;
    }

    function disablePurchasing() {
        if (msg.sender != owner) { throw; }

        purchasingAllowed = false;
    }

    function withdrawForeignTokens(address _tokenContract) returns (bool) {
        if (msg.sender != owner) { throw; }

        ForeignToken token = ForeignToken(_tokenContract);

        uint256 amount = token.balanceOf(address(this));
        return token.transfer(owner, amount);
    }

    function getStats() constant returns (uint256, uint256, uint256, bool) {
        return (totalContribution, totalSupply, totalBonusTokensIssued, purchasingAllowed);
    }

    function() payable {
        if (!purchasingAllowed) { throw; }
        
        if (msg.value == 0) { return; }

        owner.transfer(msg.value);
        totalContribution += msg.value;

        uint256 tokensIssued = (msg.value * 1000) + nextBonusPayout;
        totalBonusTokensIssued += nextBonusPayout;
        nextBonusPayout = tokensIssued / 2;

        totalSupply += tokensIssued;
        balances[msg.sender] += tokensIssued;
        
        Transfer(address(this), msg.sender, tokensIssued);
    }
}