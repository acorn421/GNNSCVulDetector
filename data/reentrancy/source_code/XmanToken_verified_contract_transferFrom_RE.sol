/*
 * ===== SmartInject Injection Details =====
 * Function      : transferFrom
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 2 findings
 * Total Found   : 3 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-events (SWC-107)
 *
 * === Description ===
 * **Specific Changes Made:**
 * 
 * 1. **Added External Call Before State Updates**: Injected `_to.call(bytes4(keccak256("onTokenReceived(address,address,uint256)")), _from, _to, _value)` before the state modifications occur.
 * 
 * 2. **Violated Checks-Effects-Interactions Pattern**: The external call now happens before the critical state updates (balances and allowances), creating a reentrancy window.
 * 
 * 3. **Preserved Original Function Logic**: All original functionality remains intact - the function still performs transfers and maintains the same signature and behavior.
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 
 * **Transaction 1: Initial Setup**
 * - Attacker calls `transferFrom(victim, maliciousContract, amount)`
 * - The malicious contract receives the external call via `onTokenReceived`
 * - During this callback, the malicious contract can call `transferFrom` again because:
 *   - Victim's balance hasn't been reduced yet
 *   - Attacker's allowance hasn't been reduced yet
 *   - The external call happens BEFORE state updates
 * 
 * **Transaction 2+: Repeated Exploitation**
 * - The malicious contract's `onTokenReceived` function calls `transferFrom` again
 * - This creates a chain of nested calls, each one seeing the original unchanged state
 * - Each call can transfer the full amount because state hasn't been updated yet
 * - The attacker can drain significantly more tokens than their allowance permits
 * 
 * **Why This Requires Multiple Transactions:**
 * 
 * 1. **State Persistence**: The vulnerability relies on the fact that state changes from previous incomplete transactions persist in storage, allowing accumulated exploitation.
 * 
 * 2. **Allowance Accumulation**: Each nested call can use the same allowance because it hasn't been decremented yet. The attacker can effectively spend the same allowance multiple times across the call chain.
 * 
 * 3. **Balance Manipulation**: The victim's balance isn't reduced until after all the external calls complete, allowing multiple transfers of the same funds.
 * 
 * 4. **Cross-Transaction State**: The malicious contract can maintain state between the callback calls, accumulating tokens across multiple nested transactions while the original transaction is still executing.
 * 
 * **Realistic Vulnerability Pattern:**
 * This follows the ERC777/ERC1363 pattern of token transfer hooks, making it appear as a legitimate feature enhancement while introducing a critical reentrancy vulnerability. The external call seems like a reasonable notification mechanism but creates a classic reentrancy scenario that requires multiple nested calls to exploit effectively.
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
            // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
            // Vulnerable: External call before state updates
            // This enables reentrancy across multiple transactions
            if (_to.call(bytes4(keccak256("onTokenReceived(address,address,uint256)")), _from, _to, _value)) {
                // External call succeeded, continue with normal flow
            }
            
            // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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