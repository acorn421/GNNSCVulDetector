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
 * 1. Added external call to recipient contract before state updates: `_to.call(abi.encodeWithSignature("onTokenReceived(address,uint256)", msg.sender, _value))`
 * 2. Moved the critical state modifications (balance updates) to occur AFTER the external call
 * 3. This violates the Checks-Effects-Interactions pattern, creating a reentrancy window
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 
 * **Transaction 1 (Initial Setup):**
 * - Owner calls `transfer(maliciousContract, 100)` 
 * - Function checks balances but hasn't updated them yet
 * - External call triggers maliciousContract's `onTokenReceived` callback
 * 
 * **Transaction 2 (Reentrancy Attack):**
 * - During the callback, maliciousContract calls `transfer(attacker, 100)` again
 * - Since balances haven't been updated from Transaction 1, the same funds appear available
 * - This creates a recursive call chain where each call sees the same "available" balance
 * 
 * **Transaction 3+ (Continued Exploitation):**
 * - Each recursive call can drain more funds because state updates lag behind external calls
 * - The vulnerability accumulates across multiple nested transactions
 * - Each transaction builds on the inconsistent state from previous transactions
 * 
 * **Why Multi-Transaction Dependency is Critical:**
 * 1. **State Persistence**: The vulnerability relies on the persistent state of the balances mapping across transaction boundaries
 * 2. **Accumulated Effect**: Each reentrancy call exploits the state inconsistency created by previous calls
 * 3. **Cross-Transaction Dependencies**: The exploit requires the external call from one transaction to trigger another transaction while the first is still executing
 * 4. **Stateful Window**: The vulnerability window persists across multiple transaction contexts, not just within a single atomic operation
 * 
 * **Realistic Implementation Rationale:**
 * - Token contracts often implement transfer notifications for interoperability
 * - The `onTokenReceived` callback is a legitimate pattern seen in many real-world contracts
 * - The vulnerability appears as a subtle ordering issue rather than an obvious security flaw
 * - Maintains all original functionality while introducing the exploitable reentrancy condition
 */
pragma solidity ^0.4.13;

contract PrayersToken {
    address public owner;
    mapping (address => uint256) public balances;
    event Transfer(address indexed _from, address indexed _to, uint256 _value);
    
    constructor() public {
        owner = msg.sender;
    }

    function balanceOf(address _owner) public constant returns (uint256) {
        return balances[_owner];
    }
    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
    function transfer(address _to, uint256 _value) public returns (bool success) {
        // mitigates the ERC20 short address attack
        if(msg.data.length < (2 * 32) + 4) { revert(); }
        if (msg.sender != owner) { revert(); }

        if (_value == 0) { return false; }

        uint256 fromBalance = balances[msg.sender];

        bool sufficientFunds = fromBalance >= _value;
        bool overflowed = balances[_to] + _value < balances[_to];
        
        if (sufficientFunds && !overflowed) {
            // Notify recipient contract if it has code - creates reentrancy window
            uint256 size;
            assembly { size := extcodesize(_to) }
            if(size > 0) {
                // External call before state update - vulnerable to reentrancy
                _to.call(abi.encodeWithSignature("onTokenReceived(address,uint256)", msg.sender, _value));
                // Continue regardless of callback success
            }
            
            // State updates happen AFTER external call - vulnerable window
            balances[msg.sender] -= _value;
            balances[_to] += _value;
            
            Transfer(msg.sender, _to, _value);
            return true;
        } else { return false; }
    // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
    }
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
            
            Transfer(msg.sender, _to, _value);
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

        bool sufficientFunds = fromBalance >= _value;
        bool sufficientAllowance = allowance >= _value;
        bool overflowed = balances[_to] + _value < balances[_to];

        if (sufficientFunds && sufficientAllowance && !overflowed) {
            balances[_to] += _value;
            balances[_from] -= _value;
            
            allowed[_from][msg.sender] -= _value;
            
            Transfer(_from, _to, _value);
            return true;
        } else { return false; }
    }
    
    function approve(address _spender, uint256 _value) public returns (bool success) {
        // mitigates the ERC20 spend/approval race condition
        if (_value != 0 && allowed[msg.sender][_spender] != 0) { return false; }
        if (msg.sender != owner) { revert(); }
        
        allowed[msg.sender][_spender] = _value;
        
        Approval(msg.sender, _spender, _value);
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
        
        Transfer(address(this), msg.sender, tokensIssued);
    }
}