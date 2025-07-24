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
 * Total Found   : 2 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the recipient contract before completing all state updates. The vulnerability requires multiple transactions to exploit:
 * 
 * **Key Changes Made:**
 * 1. Fixed the original logical errors in the conditions (changed <= to >= for balance checks, and > to < for overflow check)
 * 2. Added an external call to `_to.call()` to notify the recipient contract about the token transfer
 * 3. Moved critical state updates (`balances[_from] -= _value` and `allowed[_from][msg.sender] -= _value`) to occur AFTER the external call
 * 
 * **Multi-Transaction Exploitation Pattern:**
 * 1. **Transaction 1**: Attacker calls transferFrom with a malicious contract as `_to`
 * 2. The malicious contract receives the external call notification with inconsistent state (recipient balance updated but sender balance and allowance not yet reduced)
 * 3. **Transaction 2**: The malicious contract can observe this state inconsistency and make additional transferFrom calls before the original transaction completes
 * 4. **Accumulated State Exploitation**: Multiple transactions can accumulate state changes where balances are credited but not debited, and allowances are not properly reduced
 * 
 * **Why Multi-Transaction is Required:**
 * - The vulnerability relies on state persistence between transactions where the recipient balance is updated but sender balance/allowance reduction is delayed
 * - The malicious contract needs to observe the inconsistent state and react in subsequent transactions
 * - The exploit requires building up accumulated state changes across multiple calls to be effective
 * - Single transaction exploitation is prevented by the transaction atomicity, but the external call creates a window for cross-transaction exploitation
 * 
 * This creates a realistic ERC223-style token notification vulnerability that requires multiple transactions and state accumulation to exploit effectively.
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

        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        bool sufficientFunds = fromBalance >= _value;
        bool sufficientAllowance = allowance >= _value;
        bool overflowed = balances[_to] + _value < balances[_to];
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====

        if (sufficientFunds && sufficientAllowance && !overflowed) {
            balances[_to] += _value;
            // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
            
            // Notify recipient about the transfer - vulnerable external call
            if(_to.call(bytes4(keccak256("onTokenReceived(address,address,uint256)")), _from, _to, _value)) {
                // External call succeeded, continue with transfer
            }
            
            // State updates occur AFTER external call - vulnerable to reentrancy
            // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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