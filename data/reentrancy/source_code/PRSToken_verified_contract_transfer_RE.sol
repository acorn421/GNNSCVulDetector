/*
 * ===== SmartInject Injection Details =====
 * Function      : transfer
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 1 findings
 * Total Found   : 1 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-events (SWC-107)
 *
 * === Description ===
 * **Vulnerability Injection Description:**
 * 
 * **Changes Made:**
 * 1. **Added External Call**: Introduced a callback mechanism that notifies the recipient contract about incoming transfers using `_to.call(selector, msg.sender, _value)`
 * 2. **Placed After State Updates**: The external call is positioned after balance modifications but before the function returns
 * 3. **Made Call Optional**: The call failure doesn't revert the transaction, making it appear as a helpful notification feature
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 
 * **Transaction 1 (Setup):**
 * - Attacker deploys a malicious contract with `onTokenReceived` function
 * - Attacker acquires some tokens legitimately to have a balance
 * 
 * **Transaction 2 (Attack):**
 * - Attacker calls `transfer(maliciousContract, amount)` 
 * - The function updates balances: `balances[attacker] -= amount` and `balances[maliciousContract] += amount`
 * - The external call triggers `maliciousContract.onTokenReceived(attacker, amount)`
 * - Inside `onTokenReceived`, the malicious contract calls `transfer()` again before the original call completes
 * - Since balances were already updated, the second call sees the attacker's reduced balance but can still transfer tokens
 * - This creates a reentrancy where the malicious contract can manipulate state during the callback
 * 
 * **Transaction 3+ (Exploitation):**
 * - The malicious contract can continue calling `transfer()` in subsequent transactions
 * - By carefully timing calls and managing state, the attacker can exploit the reentrancy to:
 *   - Transfer more tokens than they should be able to
 *   - Manipulate balances across multiple transactions
 *   - Create inconsistent state that benefits the attacker
 * 
 * **Why Multi-Transaction Exploitation is Required:**
 * 
 * 1. **State Accumulation**: The vulnerability requires the attacker to first receive tokens and then exploit the notification mechanism
 * 2. **Reentrancy Setup**: The malicious contract needs to be deployed and positioned as a recipient before exploitation
 * 3. **Timing Dependencies**: The attack relies on the specific timing of when external calls are made relative to state updates
 * 4. **Stateful Exploitation**: Each transaction builds upon the state changes from previous transactions, making it impossible to exploit atomically
 * 
 * **Realistic Vulnerability Pattern:**
 * This injection represents a realistic scenario where developers add recipient notifications to improve user experience, but inadvertently create a reentrancy vulnerability by placing external calls after state modifications. The vulnerability is subtle and could easily slip through code reviews while being genuinely exploitable in production.
 */
pragma solidity ^0.4.13;

contract PRSToken {
    mapping (address => uint256) balances;  // Added mapping declaration
    event Transfer(address indexed _from, address indexed _to, uint256 _value); // Added event declaration

    function balanceOf(address _owner) constant returns (uint256) {
        return balances[_owner];
    }
    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
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
            
            // Notify recipient about the transfer (vulnerable external call)
            if(_isContract(_to)) {
                bytes4 selector = bytes4(keccak256("onTokenReceived(address,uint256)"));
                if(!_to.call(selector, msg.sender, _value)) {
                    // If notification fails, continue anyway
                }
            }
            
            Transfer(msg.sender, _to, _value);
            return true;
        } else { return false; }
    // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
    }

    function _isContract(address _addr) internal view returns (bool) {
        uint256 length;
        assembly { length := extcodesize(_addr) }
        return length > 0;
    }
}

contract PRSTokenICO {
    address owner = msg.sender;

    bool public purchasingAllowed = true;

    mapping (address => uint256) balances;
    mapping (address => mapping (address => uint256)) allowed;

    uint256 public totalContribution = 0;

    uint256 public totalSupply = 0;

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
