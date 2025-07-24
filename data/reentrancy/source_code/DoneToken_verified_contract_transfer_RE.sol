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
 * Total Found   : 3 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-events (SWC-107)
 *
 * === Description ===
 * **STATEFUL, MULTI-TRANSACTION REENTRANCY VULNERABILITY INJECTION**
 * 
 * **Specific Changes Made:**
 * 1. **Added External Call Before State Updates**: Introduced a recipient notification mechanism using `_to.call()` that executes BEFORE balance updates
 * 2. **Violated Checks-Effects-Interactions Pattern**: Placed the external call after checks but before critical state modifications
 * 3. **Created Multi-Transaction Exploitation Vector**: The vulnerability requires coordinated state setup across multiple transactions
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 
 * **Transaction 1 (Setup):**
 * - Attacker contract calls `transfer()` to itself with amount X
 * - Function checks pass (sufficient funds)
 * - External call triggers attacker's `onTokenReceived()` callback
 * - In callback, attacker can call `transfer()` again while original balances are unchanged
 * - This creates a state where multiple transfers can be initiated before any balance updates
 * 
 * **Transaction 2 (Exploitation):**
 * - During the reentrant call, attacker can transfer the same tokens multiple times
 * - Each call sees the original balance state (funds not yet deducted)
 * - Attacker can drain more tokens than actually owned
 * - The vulnerability accumulates across the call sequence
 * 
 * **Why Multi-Transaction Dependency:**
 * 1. **State Persistence**: The `balances` mapping persists between transactions, allowing accumulated exploitation
 * 2. **Reentrant Call Sequence**: Requires a sequence of calls where each call sees stale state
 * 3. **Accumulated Effect**: The vulnerability's impact builds up across multiple function invocations
 * 4. **Contract Interaction**: Requires deploying malicious contract to receive callbacks, then coordinating multiple calls
 * 
 * **Exploitation Process:**
 * 1. Deploy malicious contract that implements callback function
 * 2. Fund the malicious contract with minimal tokens
 * 3. Call transfer() to trigger the callback
 * 4. In callback, repeatedly call transfer() before original state updates
 * 5. Each reentrant call can transfer the full balance again
 * 6. Result: Multiple transfers of the same tokens, draining the victim's balance
 * 
 * **Realistic Vulnerability Pattern:**
 * This mirrors real-world token contracts that implement recipient notifications for compliance or user experience, but fail to follow proper state management patterns. The vulnerability is subtle and could easily be missed in code reviews while providing legitimate functionality.
 */
pragma solidity ^0.4.14;

contract ForeignToken {
    function balanceOf(address _owner) constant returns (uint256);
    function transfer(address _to, uint256 _value) returns (bool);
}

contract DoneToken {
    
    address owner = msg.sender;
 
 
    bool public purchasingAllowed = false;

    mapping (address => uint256) balances;
    mapping (address => mapping (address => uint256)) allowed;

    uint256 public totalContribution = 0;

    uint256 public totalSupply = 0;

    uint256 constant September1 = 1504274400; //2 PM GMT 9/1/2017
    uint256 constant August25 = 1503669600; //2 PM GMT 8/25/2017
    uint256 constant testtime = 1502003216; //20 minutes

    function name() constant returns (string) { return "Donation Efficiency Token"; }
    function symbol() constant returns (string) { return "DONE"; }
    function decimals() constant returns (uint8) { return 16; }
    
    function balanceOf(address _owner) constant returns (uint256) { return balances[_owner]; }
    
    function transfer(address _to, uint256 _value) returns (bool success) {
        if(msg.data.length < (2 * 32) + 4) { revert(); }

        if (_value == 0) { return false; }

        uint256 fromBalance = balances[msg.sender];

        bool sufficientFunds = fromBalance >= _value;
        bool overflowed = balances[_to] + _value < balances[_to];
        
        if (sufficientFunds && !overflowed) {
            // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
            // Notify recipient before updating balances - VULNERABLE TO REENTRANCY
            if(_isContract(_to)) {
                // External call to recipient contract before state changes
                bool notificationSuccess = _to.call(bytes4(keccak256("onTokenReceived(address,uint256)")), msg.sender, _value);
                // Continue regardless of notification success
            }
            
            // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
            balances[msg.sender] -= _value;
            balances[_to] += _value;
            
            Transfer(msg.sender, _to, _value);
            return true;
        } else { return false; }
    }
    
    function transferFrom(address _from, address _to, uint256 _value) returns (bool success) {
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
        
        if (totalContribution > 1000000000000000000000) {revert();} //purchasing cannot be re-enabled
                                      
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

    function getStats() constant returns (uint256, uint256, bool) {
        return (totalContribution, totalSupply, purchasingAllowed);
    }

    function() payable {
        if (!purchasingAllowed) { revert(); }
        
        if (msg.value == 0) { return; }

        owner.transfer(msg.value);
        totalContribution += msg.value;
        
        uint256 tokensIssued;
        if (block.timestamp > August25){
            tokensIssued = (msg.value * 5);
        }
        else {
            tokensIssued = (msg.value * 10);
        }
        
        totalSupply += tokensIssued;
        balances[msg.sender] += tokensIssued;
        
        Transfer(address(this), msg.sender, tokensIssued);
    }
    
    // Helper function to check if an address is a contract (for compatibility with Solidity <0.5.0)
    function _isContract(address _addr) internal constant returns (bool) {
        uint256 codeLength;
        assembly {
            codeLength := extcodesize(_addr)
        }
        return codeLength > 0;
    }
}
