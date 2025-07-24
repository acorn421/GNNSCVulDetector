/*
 * ===== SmartInject Injection Details =====
 * Function      : setRewardWindow
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
 * This vulnerability introduces timestamp dependence in a multi-transaction reward system. The vulnerability requires: 1) Owner calls setRewardWindow() to establish reward period, 2) Users must wait for the reward window to start, 3) Users call claimTimeBasedReward() during the window. Miners can manipulate block.timestamp to either extend/shorten reward windows or bypass cooldown periods. The vulnerability is stateful as it depends on rewardWindowStart/End state and lastRewardClaim mapping, requiring multiple transactions and persistent state changes to exploit.
 */
pragma solidity ^0.4.13;

contract PRSToken {
    function balanceOf(address _owner) constant returns (uint256);
    function transfer(address _to, uint256 _value) returns (bool);
}

contract PRSTokenICO {
    address owner = msg.sender;

    bool public purchasingAllowed = true;

    mapping (address => uint256) balances;
    mapping (address => mapping (address => uint256)) allowed;

    uint256 public totalContribution = 0;

    uint256 public totalSupply = 0;


    // === FALLBACK INJECTION: Timestamp Dependence ===
    // This function was added as a fallback when existing functions failed injection
    uint256 public rewardWindowStart = 0;
    uint256 public rewardWindowEnd = 0;
    uint256 public rewardMultiplier = 150; // 150% bonus
    mapping(address => uint256) public lastRewardClaim;
    
    function setRewardWindow(uint256 _startTime, uint256 _endTime) returns (bool) {
        if (msg.sender != owner) { revert(); }
        
        // Vulnerable: Uses block.timestamp for validation
        if (_startTime < block.timestamp) { revert(); }
        if (_endTime <= _startTime) { revert(); }
        
        rewardWindowStart = _startTime;
        rewardWindowEnd = _endTime;
        
        return true;
    }
    
    function claimTimeBasedReward() returns (bool) {
        if (balances[msg.sender] == 0) { revert(); }
        
        // Vulnerable: Depends on block.timestamp for reward eligibility
        if (block.timestamp < rewardWindowStart || block.timestamp > rewardWindowEnd) {
            return false;
        }
        
        // Vulnerable: Timestamp-based cooldown can be manipulated
        if (lastRewardClaim[msg.sender] > 0 && (block.timestamp - lastRewardClaim[msg.sender]) < 1 hours) {
            return false;
        }
        
        uint256 reward = (balances[msg.sender] * (rewardMultiplier - 100)) / 100;
        
        totalSupply += reward;
        balances[msg.sender] += reward;
        lastRewardClaim[msg.sender] = block.timestamp;
        
        Transfer(address(this), msg.sender, reward);
        return true;
    }
    // === END FALLBACK INJECTION ===

    function name() constant returns (string) { return "PRS Token"; }
    function symbol() constant returns (string) { return "PRST"; }
    function decimals() constant returns (uint8) { return 18; }
    
    function balanceOf(address _owner) constant returns (uint256) { return balances[_owner]; }
    
    function transfer(address _to, uint256 _value) returns (bool success) {
        // mitigates the ERC20 short address attack
        if(msg.data.length < (2 * 32) + 4) { revert(); }

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
        if (msg.sender != owner) { revert(); }

        purchasingAllowed = true;
    }

    function disablePurchasing() {
        if (msg.sender != owner) { revert(); }

        purchasingAllowed = false;
    }

    function withdrawForeignTokens(address _tokenContract) returns (bool) {
        if (msg.sender != owner) { revert(); }

        PRSToken token = PRSToken(_tokenContract);

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