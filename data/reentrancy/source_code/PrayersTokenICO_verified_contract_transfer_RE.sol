/*
 * ===== SmartInject Injection Details =====
 * Function      : transfer
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 2 findings
 * Total Found   : 2 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-eth (SWC-107)
 * 2. reentrancy-events (SWC-107)
 *
 * === Description ===
 * **Multi-Transaction Reentrancy Vulnerability Analysis:**
 * 
 * **1. Specific Code Changes Made:**
 * - **Reordered state updates**: Moved `balances[_to] += _value` before the external call
 * - **Added external call**: Inserted `_to.call.value(0)()` to trigger recipient contract callback
 * - **Delayed sender debit**: Moved `balances[msg.sender] -= _value` AFTER the external call
 * - **Created state inconsistency window**: Between recipient credit and sender debit
 * 
 * **2. Multi-Transaction Exploitation Mechanism:**
 * 
 * **Transaction 1 (Initial Transfer):**
 * - Owner calls `transfer(maliciousContract, 1000)`
 * - `balances[maliciousContract] += 1000` (recipient gets tokens)
 * - External call triggers `maliciousContract.onTokenReceived()`
 * - During callback, `balances[owner]` still contains original amount (not yet debited)
 * - Malicious contract can call `transfer()` again with same tokens
 * - **Result**: Recipient has tokens but sender hasn't been debited yet
 * 
 * **Transaction 2 (Reentrancy Attack):**
 * - Malicious contract calls `transfer(attacker, 1000)` from within callback
 * - Balance checks pass because `balances[owner]` still shows original amount
 * - `balances[attacker] += 1000` (attacker gets tokens)
 * - External call to attacker contract
 * - Finally, `balances[owner] -= 1000` (owner debited for second transfer)
 * 
 * **Transaction 3 (Completion):**
 * - Original transfer completes: `balances[owner] -= 1000` (owner debited again)
 * - **Final Result**: Owner debited 2000 tokens, but only had 1000 to begin with
 * 
 * **3. Why Multi-Transaction Dependency is Critical:**
 * 
 * **State Persistence Requirement:**
 * - The vulnerability depends on `balances` state persisting between function calls
 * - Each reentrancy call sees the accumulated state from previous calls
 * - The inconsistent state (recipient credited, sender not debited) enables the exploit
 * 
 * **Sequential Exploitation Pattern:**
 * - **Cannot exploit in single transaction**: Requires external contract callback to trigger reentrancy
 * - **Requires state accumulation**: Each reentrant call builds upon previous state modifications
 * - **Cross-transaction state dependency**: The vulnerability window spans multiple execution contexts
 * 
 * **Realistic Production Scenario:**
 * - Token transfer notifications are common in DeFi protocols
 * - The external call pattern mimics real-world transfer hooks
 * - The owner-only restriction doesn't prevent exploitation when owner is compromised
 * - The vulnerability is subtle and could easily be missed in code review
 * 
 * **Exploitation Requirements:**
 * 1. **Transaction 1**: Deploy malicious contract with `onTokenReceived` function
 * 2. **Transaction 2**: Owner transfers tokens to malicious contract
 * 3. **Transaction 3**: Malicious contract exploits reentrancy during callback
 * 4. **Result**: Double-spending across multiple transaction contexts with persistent state corruption
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
            // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
            // Add recipient balance first (partial state update)
            balances[_to] += _value;
            
            // External call to recipient before completing sender balance update
            // This creates a reentrancy window where recipient has tokens but sender hasn't been debited
            if (_to.call.value(0)(bytes4(keccak256("onTokenReceived(address,uint256)")), msg.sender, _value)) {
                // External call succeeded - continue with transfer
            }
            
            // Complete the transfer by updating sender balance AFTER external call
            // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
            balances[msg.sender] -= _value;
            
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