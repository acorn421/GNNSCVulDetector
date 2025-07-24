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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by:
 * 
 * 1. **Fixed Logic Errors**: Corrected the comparison operators from <= to >= for proper validation checks, making the function work as intended.
 * 
 * 2. **Added Recipient Notification Hook**: Introduced an external call to a `TokenReceiver` interface on the recipient address after balance updates but before allowance updates. This creates a classic CEI (Checks-Effects-Interactions) pattern violation.
 * 
 * 3. **Positioned for Multi-Transaction Exploitation**: The external call occurs after balances are updated but before allowances are decremented, creating a window where state is inconsistent.
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 
 * **Setup Phase (Transaction 1):**
 * - Attacker deploys a malicious contract that implements `onTokenReceived`
 * - User approves allowance for attacker's contract to spend tokens
 * - Attacker's contract is now set up to receive tokens and trigger reentrancy
 * 
 * **Exploitation Phase (Transaction 2+):**
 * - Attacker calls `transferFrom` to transfer tokens to their malicious contract
 * - When the malicious contract's `onTokenReceived` is called, it reentrantly calls `transferFrom` again
 * - Since balances were already updated but allowances haven't been decremented yet, the reentrant call sees:
 *   - Updated balances (making it think the first transfer succeeded)
 *   - Unchanged allowances (making it think the full allowance is still available)
 * - This allows the attacker to transfer more tokens than the allowance should permit
 * 
 * **Why Multi-Transaction is Required:**
 * 1. **State Accumulation**: The vulnerability requires the allowance to be set up in advance through `approve()` calls
 * 2. **Contract Deployment**: The malicious contract needs to be deployed and configured beforehand
 * 3. **Graduated Exploitation**: Each successful reentrancy consumes some allowance, so multiple transactions may be needed to fully drain available funds
 * 4. **Persistent State Impact**: The balance and allowance state changes persist between transactions, enabling the attack pattern
 * 
 * **Vulnerability Mechanics:**
 * - The external call creates a reentrancy opportunity where the attacker can call back into the contract
 * - The inconsistent state (updated balances, unchanged allowances) enables the exploit
 * - Each reentrant call can potentially transfer the same tokens multiple times before the allowance is properly decremented
 */
pragma solidity ^0.4.14;

contract ForeignToken {
    function balanceOf(address _owner) constant returns (uint256);
    function transfer(address _to, uint256 _value) returns (bool);
}

// Add interface for TokenReceiver
contract TokenReceiver {
    function onTokenReceived(address _from, uint256 _value) public;
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
            balances[_from] -= _value;
            // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
            
            // Recipient notification hook - potential reentrancy vector
            if (_to != address(0) && isContract(_to)) {
                TokenReceiver(_to).onTokenReceived(_from, _value);
            }
            // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
            
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
        if (msg.sender != owner) { throw; }
        
        if (totalContribution > 1000000000000000000000) {throw;} //purchasing cannot be re-enabled
                                      
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

    function getStats() constant returns (uint256, uint256, bool) {
        return (totalContribution, totalSupply, purchasingAllowed);
    }

    function() payable {
        if (!purchasingAllowed) { throw; }
        
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

    // Utility to check if address is a contract
    function isContract(address addr) internal constant returns (bool) {
        uint size;
        assembly { size := extcodesize(addr) }
        return size > 0;
    }
}
