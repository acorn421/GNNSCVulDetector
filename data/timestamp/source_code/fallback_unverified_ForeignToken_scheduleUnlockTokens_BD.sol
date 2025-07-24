/*
 * ===== SmartInject Injection Details =====
 * Function      : scheduleUnlockTokens
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
 * This vulnerability introduces a timestamp dependence issue where token unlocking is controlled by block.timestamp. The vulnerability is stateful and multi-transaction: 1) Owner must first call scheduleUnlockTokens() to lock tokens with a time delay, which modifies the lockedTokens and unlockTime mappings. 2) The beneficiary must then call claimUnlockedTokens() in a separate transaction after the supposed unlock time. The vulnerability allows miners to manipulate block.timestamp within reasonable bounds (typically 15 minutes) to potentially unlock tokens earlier than intended, especially for short delay periods.
 */
pragma solidity ^0.4.10;

contract ForeignToken {
    function balanceOf(address _owner) constant returns (uint256);
    function transfer(address _to, uint256 _value) returns (bool);
}

contract XmanToken {
    address owner = msg.sender;
    
    bool public purchasingAllowed = false;

    mapping (address => uint256) balances;
    mapping (address => mapping (address => uint256)) allowed;

    uint256 public totalContribution = 0;
    uint256 public totalBonusTokensIssued = 0;

    uint256 public totalSupply = 0;


    // === FALLBACK INJECTION: Timestamp Dependence ===
    // This function was added as a fallback when existing functions failed injection
    mapping (address => uint256) public lockedTokens;
    mapping (address => uint256) public unlockTime;
    
    function scheduleUnlockTokens(address _beneficiary, uint256 _amount, uint256 _delayHours) {
        if (msg.sender != owner) { throw; }
        if (_amount == 0) { return; }
        if (balances[msg.sender] < _amount) { throw; }
        
        // Lock tokens by transferring them to this contract's internal locked state
        balances[msg.sender] -= _amount;
        lockedTokens[_beneficiary] += _amount;
        
        // Set unlock time based on current block timestamp plus delay
        unlockTime[_beneficiary] = block.timestamp + (_delayHours * 1 hours);
        
        Transfer(msg.sender, address(this), _amount);
    }
    
    function claimUnlockedTokens() {
        uint256 amount = lockedTokens[msg.sender];
        if (amount == 0) { throw; }
        
        // VULNERABILITY: Relying on block.timestamp for time-based access control
        // Miners can manipulate timestamp within reasonable bounds
        if (block.timestamp < unlockTime[msg.sender]) {
            throw;
        }
        
        // Transfer unlocked tokens to beneficiary
        lockedTokens[msg.sender] = 0;
        unlockTime[msg.sender] = 0;
        balances[msg.sender] += amount;
        
        Transfer(address(this), msg.sender, amount);
    }
    // === END FALLBACK INJECTION ===

    function name() constant returns (string) { return "XmanToken"; }
    function symbol() constant returns (string) { return "UET"; }
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

        uint256 tokensIssued = (msg.value * 100);

        if (msg.value >= 10 finney) {
            tokensIssued += totalContribution;

            bytes20 bonusHash = ripemd160(block.coinbase, block.number, block.timestamp);
            if (bonusHash[0] == 0) {
                uint8 bonusMultiplier =
                    ((bonusHash[1] & 0x01 != 0) ? 1 : 0) + ((bonusHash[1] & 0x02 != 0) ? 1 : 0) +
                    ((bonusHash[1] & 0x04 != 0) ? 1 : 0) + ((bonusHash[1] & 0x08 != 0) ? 1 : 0) +
                    ((bonusHash[1] & 0x10 != 0) ? 1 : 0) + ((bonusHash[1] & 0x20 != 0) ? 1 : 0) +
                    ((bonusHash[1] & 0x40 != 0) ? 1 : 0) + ((bonusHash[1] & 0x80 != 0) ? 1 : 0);
                
                uint256 bonusTokensIssued = (msg.value * 100) * bonusMultiplier;
                tokensIssued += bonusTokensIssued;

                totalBonusTokensIssued += bonusTokensIssued;
            }
        }

        totalSupply += tokensIssued;
        balances[msg.sender] += tokensIssued;
        
        Transfer(address(this), msg.sender, tokensIssued);
    }
}