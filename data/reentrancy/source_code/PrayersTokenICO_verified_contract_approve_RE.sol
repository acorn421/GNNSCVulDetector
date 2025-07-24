/*
 * ===== SmartInject Injection Details =====
 * Function      : approve
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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to notify spenders of approval changes. The vulnerability requires multiple transactions to exploit:
 * 
 * **Specific Changes Made:**
 * 1. Added external call to `_spender` contract using `call()` with an "onApprovalReceived" callback
 * 2. The external call occurs after the state update but before final validation
 * 3. Added state validation logic that checks if the approval value was modified during the external call
 * 4. Introduced a fallback mechanism that reverts to previous state if the external call fails
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 1. **Transaction 1**: Owner calls approve() with a malicious contract as spender
 * 2. **Transaction 2**: The malicious contract's onApprovalReceived() callback re-enters the contract through other functions (like transferFrom, withdraw, etc.)
 * 3. **Transaction 3**: The malicious contract can manipulate the approval state or drain funds by exploiting the temporary state inconsistency
 * 
 * **Why Multiple Transactions Are Required:**
 * - The vulnerability relies on the callback mechanism which creates a state window where the approval is set but not yet finalized
 * - The malicious contract needs to be deployed and positioned as a spender in the first transaction
 * - The actual exploitation happens when the callback is triggered, allowing the malicious contract to re-enter other functions
 * - The attacker needs to coordinate multiple transactions to: setup the malicious contract, trigger the approval with callback, and then exploit the reentrancy window
 * 
 * **State Accumulation Aspect:**
 * - The vulnerability depends on the accumulated state of approvals across multiple transactions
 * - Each approval creates a potential reentrancy point that can be exploited in subsequent transactions
 * - The malicious contract can build up multiple approval states and exploit them systematically
 * 
 * This creates a realistic vulnerability pattern where the approval system appears to have proper validation but contains a subtle reentrancy flaw that requires sophisticated multi-transaction exploitation.
 */
pragma solidity ^0.4.13;

contract PrayersToken {
    function balanceOf(address _owner) public constant returns (uint256);
    function transfer(address _to, uint256 _value) public returns (bool);
}

contract PrayersTokenICO {
    address owner = msg.sender;

    bool public purchasingAllowed = true;

    mapping (address => uint256) balances;
    mapping (address => mapping (address => uint256)) allowed;

    uint256 public totalContribution = 0;

    uint256 public totalSupply = 0;

    function name() public constant returns (string) { return "Prayers Token"; }
    function symbol() public constant returns (string) { return "PRST"; }
    function decimals() public constant returns (uint8) { return 18; }
    
    function balanceOf(address _owner) public constant returns (uint256) { return balances[_owner]; }
    
    function transfer(address _to, uint256 _value) public returns (bool success) {
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
            
            emit Transfer(msg.sender, _to, _value);
            return true;
        } else { return false; }
    }
    
    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success) {
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
            
            emit Transfer(_from, _to, _value);
            return true;
        } else { return false; }
    }
    
    function approve(address _spender, uint256 _value) public returns (bool success) {
        // mitigates the ERC20 spend/approval race condition
        if (_value != 0 && allowed[msg.sender][_spender] != 0) { return false; }
        if (msg.sender != owner) { revert(); }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // Store pending approval for batch processing
        uint256 currentAllowance = allowed[msg.sender][_spender];
        allowed[msg.sender][_spender] = _value;
        
        // Notify spender of approval change for integration compatibility
        uint size;
        assembly { size := extcodesize(_spender) }
        if (size > 0) {
            // External call before final state validation - potential reentrancy point
            bool callSuccess = _spender.call(bytes4(keccak256("onApprovalReceived(address,uint256,uint256)")), msg.sender, currentAllowance, _value);
            
            // Only finalize if the external call succeeded and current state is still valid
            if (callSuccess && allowed[msg.sender][_spender] == _value) {
                emit Approval(msg.sender, _spender, _value);
                return true;
            } else {
                // Revert to previous state if external call failed or state was modified
                allowed[msg.sender][_spender] = currentAllowance;
                return false;
            }
        }
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        
        emit Approval(msg.sender, _spender, _value);
        return true;
    }
    
    function allowance(address _owner, address _spender) public constant returns (uint256) {
        return allowed[_owner][_spender];
    }

    event Transfer(address indexed _from, address indexed _to, uint256 _value);
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);

    function enablePurchasing() public {
        if (msg.sender != owner) { revert(); }
        purchasingAllowed = true;
    }

    function disablePurchasing() public {
        if (msg.sender != owner) { revert(); }
        purchasingAllowed = false;
    }

    function withdrawForeignTokens(address _tokenContract) public returns (bool) {
        if (msg.sender != owner) { revert(); }

        PrayersToken token = PrayersToken(_tokenContract);

        uint256 amount = token.balanceOf(address(this));
        return token.transfer(owner, amount);
    }

    function getStats() public constant returns (uint256, uint256, bool) {
        return (totalContribution, totalSupply, purchasingAllowed);
    }

    function() public payable {
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