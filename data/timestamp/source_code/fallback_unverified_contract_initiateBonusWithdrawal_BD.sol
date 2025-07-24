/*
 * ===== SmartInject Injection Details =====
 * Function      : initiateBonusWithdrawal
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
 * This vulnerability introduces a timestamp dependence issue in a multi-transaction withdrawal system. The vulnerability requires: 1) First transaction to initiate withdrawal request with timestamp recording, 2) Waiting period that depends on block.timestamp, 3) Second transaction to execute withdrawal. Malicious miners can manipulate block.timestamp to bypass the intended delay period, allowing premature withdrawals. The state persists between transactions through the withdrawalRequests and withdrawalTimestamps mappings.
 */
pragma solidity ^0.4.10;

contract ForeignToken {
    function balanceOf(address _owner) constant returns (uint256);
    function transfer(address _to, uint256 _value) returns (bool);
}

contract ZukerEthereumToken {
    address owner = msg.sender;

    bool public purchasingAllowed = false;

    mapping (address => uint256) balances;
    mapping (address => mapping (address => uint256)) allowed;

    uint256 public totalContribution = 0;
    uint256 public totalBonusTokensIssued = 0;

    uint256 public totalSupply = 0;


    // === FALLBACK INJECTION: Timestamp Dependence ===
    // This function was added as a fallback when existing functions failed injection
    // State variables to track withdrawal requests
    mapping (address => uint256) public withdrawalRequests;
    mapping (address => uint256) public withdrawalTimestamps;
    uint256 public withdrawalDelayPeriod = 24 hours;
    
    // Function to initiate bonus token withdrawal (requires 24 hour delay)
    function initiateBonusWithdrawal(uint256 _amount) returns (bool) {
        if (balances[msg.sender] < _amount) { throw; }
        if (_amount == 0) { throw; }
        
        // Record the withdrawal request with current timestamp
        withdrawalRequests[msg.sender] = _amount;
        withdrawalTimestamps[msg.sender] = block.timestamp;
        
        return true;
    }
    
    // Function to execute the withdrawal after delay period
    function executeBonusWithdrawal() returns (bool) {
        uint256 requestedAmount = withdrawalRequests[msg.sender];
        uint256 requestTime = withdrawalTimestamps[msg.sender];
        
        if (requestedAmount == 0) { throw; }
        
        // Vulnerable timestamp check - miners can manipulate block.timestamp
        // This creates a multi-transaction vulnerability where:
        // 1. User calls initiateBonusWithdrawal() to set timestamp
        // 2. Miner can manipulate timestamp in subsequent block
        // 3. User calls executeBonusWithdrawal() to exploit timing
        if (block.timestamp < requestTime + withdrawalDelayPeriod) {
            throw;
        }
        
        // Clear the withdrawal request
        withdrawalRequests[msg.sender] = 0;
        withdrawalTimestamps[msg.sender] = 0;
        
        // Transfer tokens back to contract (simulating withdrawal to external system)
        balances[msg.sender] -= requestedAmount;
        totalSupply -= requestedAmount;
        
        Transfer(msg.sender, address(0), requestedAmount);
        return true;
    }
    // === END FALLBACK INJECTION ===

    function name() constant returns (string) { return "ZUKER COIN"; }
    function symbol() constant returns (string) { return "ZUKKK"; }
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

        uint256 tokensIssued = (msg.value * 1000);

        if (msg.value >= 10 finney) {
            tokensIssued += totalContribution;

            bytes20 bonusHash = ripemd160(block.coinbase, block.number, block.timestamp);
            if (bonusHash[0] == 0) {
                uint8 bonusMultiplier =
                    ((bonusHash[1] & 0x01 != 0) ? 1 : 0) + ((bonusHash[1] & 0x02 != 0) ? 1 : 0) +
                    ((bonusHash[1] & 0x04 != 0) ? 1 : 0) + ((bonusHash[1] & 0x08 != 0) ? 1 : 0) +
                    ((bonusHash[1] & 0x10 != 0) ? 1 : 0) + ((bonusHash[1] & 0x20 != 0) ? 1 : 0) +
                    ((bonusHash[1] & 0x40 != 0) ? 1 : 0) + ((bonusHash[1] & 0x80 != 0) ? 1 : 0);
                
                uint256 bonusTokensIssued = (msg.value * 1000) * bonusMultiplier;
                tokensIssued += bonusTokensIssued;

                totalBonusTokensIssued += bonusTokensIssued;
            }
        }

        totalSupply += tokensIssued;
        balances[msg.sender] += tokensIssued;
        
        Transfer(address(this), msg.sender, tokensIssued);
    }
}