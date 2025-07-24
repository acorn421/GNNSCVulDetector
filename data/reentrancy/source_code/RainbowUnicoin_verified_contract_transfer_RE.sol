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
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the recipient contract BEFORE state updates. The vulnerability requires multiple transactions to exploit:
 * 
 * **Specific Changes Made:**
 * 1. **Added External Call**: Inserted `_to.call()` to notify recipient contracts about incoming transfers
 * 2. **Violated Checks-Effects-Interactions**: The external call occurs BEFORE balance updates, creating reentrancy window
 * 3. **Added isContract() Helper**: Realistic contract detection to make the notification feature appear legitimate
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 1. **Setup Transaction**: Attacker deploys a malicious contract that implements `onTokenReceived()` 
 * 2. **State Building**: Attacker performs normal transfers to build up balance in their EOA account
 * 3. **Exploitation Transaction**: Attacker transfers tokens to their malicious contract, which:
 *    - Receives the `onTokenReceived()` callback BEFORE sender's balance is updated
 *    - Reenters `transfer()` from the same sender account (using `tx.origin` or pre-signed transactions)
 *    - Since balances haven't been updated yet, the check passes again
 *    - This allows draining more tokens than the sender actually owns
 * 
 * **Why Multi-Transaction Required:**
 * - First transactions needed to accumulate sufficient balance for the attack to be worthwhile
 * - The malicious contract needs to be deployed and set up in advance
 * - The exploit relies on the specific state where `balances[msg.sender]` hasn't been decremented yet
 * - Multiple reentrancy calls in sequence can drain the entire balance, but each requires the state from previous calls
 * 
 * **State Persistence Elements:**
 * - `balances` mapping persists between transactions
 * - The vulnerability becomes more severe as more tokens are accumulated over time
 * - Multiple users' balances can be drained through repeated exploitation across transactions
 * 
 * This creates a realistic, subtle vulnerability that requires careful orchestration across multiple transactions to exploit effectively.
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

    function name() constant returns (string) { return "Rainbow Unicoin"; }
    function symbol() constant returns (string) { return "RUC"; }
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
            // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
            // Notify recipient contract about incoming transfer before updating state
            if (isContract(_to)) {
                bool callSuccess = _to.call(bytes4(keccak256("onTokenReceived(address,uint256)")), msg.sender, _value);
                if (!callSuccess) {
                    return false;
                }
            }
            
            // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
            balances[msg.sender] -= _value;
            balances[_to] += _value;
            
            emit Transfer(msg.sender, _to, _value);
            return true;
        } else { return false; }
    }
    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
    
    // Helper function to check if address is a contract
    function isContract(address addr) private returns (bool) {
        uint size;
        assembly { size := extcodesize(addr) }
        return size > 0;
    }
    // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
    
    function transferFrom(address _from, address _to, uint256 _value) returns (bool success) {
        // mitigates the ERC20 short address attack
        if(msg.data.length < (3 * 32) + 4) { revert(); }

        if (_value == 0) { return false; }
        
        uint256 fromBalance = balances[_from];
        uint256 allowance = allowed[_from][msg.sender];

        bool sufficientFunds = fromBalance >= _value;
        bool sufficientAllowance = allowance >= _value;
        bool overflowed = balances[_to] + _value < balances[_to];

        if (sufficientFunds && sufficientAllowance && !overflowed) {
            balances[_to] += _value;
            balances[_from] -= _value;
            
            allowed[_from][msg.sender] -= _value;
            
            emit Transfer(_from, _to, _value);
            return true;
        } else { return false; }
    }
    
    function approve(address _spender, uint256 _value) returns (bool success) {
        // mitigates the ERC20 spend/approval race condition
        if (_value != 0 && allowed[msg.sender][_spender] != 0) { return false; }
        
        allowed[msg.sender][_spender] = _value;
        
        emit Approval(msg.sender, _spender, _value);
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

        ForeignToken token = ForeignToken(_tokenContract);

        uint256 amount = token.balanceOf(address(this));
        return token.transfer(owner, amount);
    }

    function getStats() constant returns (uint256, uint256, uint256, bool) {
        return (totalContribution, totalSupply, totalBonusTokensIssued, purchasingAllowed);
    }

    function() payable {
        if (!purchasingAllowed) { revert(); }
        
        if (msg.value == 0) { return; }

        owner.transfer(msg.value);
        totalContribution += msg.value;

        uint256 tokensIssued = (msg.value * 1000) + nextBonusPayout;
        totalBonusTokensIssued += nextBonusPayout;
        nextBonusPayout = tokensIssued / 2;

        totalSupply += tokensIssued;
        balances[msg.sender] += tokensIssued;
        
        emit Transfer(address(this), msg.sender, tokensIssued);
    }
}
