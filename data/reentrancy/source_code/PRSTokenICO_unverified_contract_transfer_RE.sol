/*
 * ===== SmartInject Injection Details =====
 * Function      : transfer
 * Vulnerability : Reentrancy
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 1 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the recipient address after state modifications. The vulnerability requires multiple transactions to exploit:
 * 
 * **Specific Changes Made:**
 * 1. Added contract existence check using `_to.code.length > 0`
 * 2. Introduced external call to recipient's `onTokenReceived` function after balance updates
 * 3. External call occurs AFTER critical state changes (balances updated)
 * 4. No reentrancy protection mechanisms in place
 * 
 * **Multi-Transaction Exploitation Pattern:**
 * 1. **Transaction 1**: Attacker transfers tokens to malicious contract, establishing initial balance state
 * 2. **Transaction 2**: Attacker calls transfer again; the malicious contract's `onTokenReceived` can now reenter
 * 3. **Transaction 3+**: Accumulated state changes from previous transactions enable complex exploitation
 * 
 * **Why Multi-Transaction Required:**
 * - Initial transaction establishes the balance state needed for exploitation
 * - Subsequent transactions can exploit the persistent balance state through reentrancy
 * - The vulnerability leverages state accumulated across multiple transaction boundaries
 * - Each transaction's state changes persist in the `balances` mapping between calls
 * 
 * **Exploitation Scenario:**
 * - Attacker deploys malicious contract with `onTokenReceived` function
 * - First transfer establishes balance state
 * - Second transfer triggers callback, enabling reentrancy with known state
 * - Malicious contract can call transfer again before original transaction completes
 * - State persistence allows building complex exploitation patterns across transactions
 * 
 * The vulnerability is realistic as it mimics modern ERC20 extensions with transfer hooks, but violates the checks-effects-interactions pattern by placing external calls after state modifications.
 */
pragma solidity ^0.4.13;

contract PRSToken {
    function balanceOf(address _owner) constant returns (uint256);
    function transfer(address _to, uint256 _value) returns (bool);
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
            
            emit Transfer(msg.sender, _to, _value);
            // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
            
            // Notify recipient contract if it's a contract address
            // This creates a reentrancy vector after state changes
            if (isContract(_to)) {
                // Call recipient's onTokenReceived function
                _to.call(
                    abi.encodeWithSignature("onTokenReceived(address,uint256)", msg.sender, _value)
                );
                // Continue execution regardless of callback success
            }
            
            // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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

        PRSToken token = PRSToken(_tokenContract);

        uint256 amount = token.balanceOf(address(this));
        return token.transfer(owner, amount);
    }

    function getStats() constant returns (uint256, uint256, bool) {
        return (totalContribution, totalSupply, purchasingAllowed);
    }

    function isContract(address _addr) internal view returns (bool) {
        uint256 length;
        assembly { length := extcodesize(_addr) }
        return length > 0;
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
        
        emit Transfer(address(this), msg.sender, tokensIssued);
    }
}