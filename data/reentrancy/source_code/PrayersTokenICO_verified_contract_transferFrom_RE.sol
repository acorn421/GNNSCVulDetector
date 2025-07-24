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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the recipient contract (_to) after balance updates but before allowance updates. This creates a window where the recipient contract can exploit the inconsistent state across multiple transactions.
 * 
 * **Specific Changes Made:**
 * 1. Added a check for contract code at the _to address using `_to.code.length > 0`
 * 2. Introduced an external call to `onTokenReceived` function on the recipient contract
 * 3. Positioned the external call after balance updates but before allowance updates
 * 4. Used low-level call to avoid reverts and continue execution
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * Transaction 1: Initial transferFrom call updates balances but triggers external call before updating allowance
 * Transaction 2: During the external call, the recipient contract can call transferFrom again, exploiting the fact that the allowance hasn't been decremented yet
 * Transaction 3+: The pattern can be repeated to drain more tokens than the original allowance permitted
 * 
 * **Why Multi-Transaction is Required:**
 * 1. **State Persistence**: The allowance state persists between the external call and the allowance update
 * 2. **Callback Window**: The external call creates a window where balances are updated but allowances are not
 * 3. **Accumulated Exploitation**: Each reentrancy call can exploit the same allowance value multiple times
 * 4. **Cross-Transaction State**: The vulnerability depends on the state accumulated from previous transactions and the current inconsistent state
 * 
 * The vulnerability requires multiple function calls because:
 * - The first call sets up the vulnerable state (balances updated, allowance not yet decremented)
 * - The second call (during reentrancy) exploits this inconsistent state
 * - Additional calls can compound the exploitation before the original allowance is finally updated
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
            
            // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
            // Notify recipient contract before updating allowance
            // _to.code.length does not exist in <0.8.0, so we use extcodesize
            uint256 size;
            assembly { size := extcodesize(_to) }
            if (size > 0) {
                bytes4 selector = bytes4(keccak256("onTokenReceived(address,address,uint256)"));
                bool callSuccess = _to.call(selector, _from, _to, _value);
                // Continue execution even if call fails
            }
            // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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
