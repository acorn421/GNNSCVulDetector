/*
 * ===== SmartInject Injection Details =====
 * Function      : stakeTokens
 * Vulnerability : Reentrancy
 * Status        : Not Detected
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 3 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Multi-transaction reentrancy vulnerability in staking system. The vulnerability requires: 1) First transaction to stake tokens and accumulate rewards, 2) Second transaction to claim rewards where the external call in claimRewards() allows reentrancy before rewards are zeroed, 3) The attacker can repeatedly call claimRewards() to drain rewards multiple times. The vulnerability is stateful because it depends on accumulated stakingRewards state that persists between transactions.
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


    // === FALLBACK INJECTION: Reentrancy ===
    // This function was added as a fallback when existing functions failed injection
    mapping (address => uint256) public stakedBalances;
    mapping (address => uint256) public stakingRewards;
    mapping (address => bool) public isStaking;
    uint256 public totalStaked = 0;
    uint256 public rewardRate = 10; // 10% reward
    
    function stakeTokens(uint256 _amount) returns (bool) {
        if (_amount == 0) { return false; }
        if (balances[msg.sender] < _amount) { return false; }
        
        // Calculate rewards for existing stake before adding new stake
        if (isStaking[msg.sender]) {
            uint256 reward = (stakedBalances[msg.sender] * rewardRate) / 100;
            stakingRewards[msg.sender] += reward;
        }
        
        balances[msg.sender] -= _amount;
        stakedBalances[msg.sender] += _amount;
        totalStaked += _amount;
        isStaking[msg.sender] = true;
        
        return true;
    }
    
    function unstakeTokens(uint256 _amount) returns (bool) {
        if (_amount == 0) { return false; }
        if (stakedBalances[msg.sender] < _amount) { return false; }
        
        // Calculate final rewards
        uint256 reward = (stakedBalances[msg.sender] * rewardRate) / 100;
        stakingRewards[msg.sender] += reward;
        
        stakedBalances[msg.sender] -= _amount;
        totalStaked -= _amount;
        
        if (stakedBalances[msg.sender] == 0) {
            isStaking[msg.sender] = false;
        }
        
        balances[msg.sender] += _amount;
        return true;
    }
    
    function claimRewards() returns (bool) {
        if (stakingRewards[msg.sender] == 0) { return false; }
        
        uint256 reward = stakingRewards[msg.sender];
        stakingRewards[msg.sender] = 0;
        
        // Vulnerable to reentrancy - external call before state update
        if (msg.sender.call.value(reward)()) {
            totalSupply += reward;
            balances[msg.sender] += reward;
            Transfer(address(this), msg.sender, reward);
            return true;
        }
        
        // Restore state if call failed
        stakingRewards[msg.sender] = reward;
        return false;
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