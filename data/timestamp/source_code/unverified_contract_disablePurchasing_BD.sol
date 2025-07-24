/*
 * ===== SmartInject Injection Details =====
 * Function      : disablePurchasing
 * Vulnerability : Timestamp Dependence
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
 * Injected a stateful, multi-transaction Timestamp Dependence vulnerability by implementing a time-based cooldown and delayed execution system. The vulnerability requires multiple transactions to exploit:
 * 
 * **Changes Made:**
 * 1. Added `lastDisableAttempt` mapping to track when each address last attempted to disable
 * 2. Added `DISABLE_COOLDOWN` constant requiring 5 minutes between disable attempts
 * 3. Added `disableScheduledAt` state variable to store when disable was scheduled
 * 4. Added `DISABLE_DELAY` constant requiring 10 minutes delay before disable takes effect
 * 5. Modified function to require two separate transactions: first to schedule, second to execute
 * 
 * **Multi-Transaction Exploitation:**
 * 1. **Transaction 1**: Owner calls `disablePurchasing()` to schedule disable for `block.timestamp + 600`
 * 2. **State Persistence**: `disableScheduledAt` and `lastDisableAttempt` are stored on-chain
 * 3. **Miner Manipulation**: Miners can manipulate `block.timestamp` in subsequent blocks
 * 4. **Transaction 2**: Owner calls `disablePurchasing()` again after delay period
 * 5. **Exploitation**: If miner sets `block.timestamp` to be less than `disableScheduledAt`, the disable fails but cooldown is reset
 * 6. **Continued Exploitation**: Multiple transactions can be used to repeatedly reset cooldowns and prevent disabling
 * 
 * **Why Multi-Transaction is Required:**
 * - The vulnerability requires at least 2 transactions separated by time delay
 * - State variables (`disableScheduledAt`, `lastDisableAttempt`) must persist between transactions
 * - Miners can only manipulate timestamp within reasonable bounds per block
 * - The exploit requires temporal manipulation across multiple blocks/transactions
 * - Single transaction cannot exploit the time-based logic due to delay requirements
 * 
 * **Realistic Vulnerability Pattern:**
 * This mimics real-world patterns where contracts implement time-based security mechanisms that can be manipulated by miners controlling block timestamps, requiring multiple transactions to fully exploit the timing dependencies.
 */
pragma solidity ^0.4.11;

contract NGToken {

    function NGToken() {}
    
    address public niceguy1 = 0x589A1E14208433647863c63fE2C736Ce930B956b;
    address public niceguy2 = 0x583f354B6Fff4b11b399Fad8b3C2a73C16dF02e2;
    address public niceguy3 = 0x6609867F516A15273678d268460B864D882156b6;
    address public niceguy4 = 0xA4CA81EcE0d3230c6f8CCD0ad94f5a5393f76Af8;
    address public owner = msg.sender;
    mapping (address => uint256) balances;
    mapping (address => mapping (address => uint256)) allowed;
    uint256 public totalContribution = 0;
    uint256 public totalBonusTokensIssued = 0;
    uint256 public totalSupply = 0;
    bool public purchasingAllowed = true;

    function name() constant returns (string) { return "Nice Guy Token"; }
    function symbol() constant returns (string) { return "NGT"; }
    function decimals() constant returns (uint256) { return 18; }
    
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
        } else { 
            return false; 
        }
    }
    
    function approve(address _spender, uint256 _value) returns (bool success) {
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

    // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
mapping(address => uint256) public lastDisableAttempt;
    uint256 public constant DISABLE_COOLDOWN = 300; // 5 minutes in seconds
    uint256 public disableScheduledAt;
    uint256 public constant DISABLE_DELAY = 600; // 10 minutes delay
    
    function disablePurchasing() {
        if (msg.sender != owner) { throw; }
        
        // Check if enough time has passed since last disable attempt
        if (block.timestamp < lastDisableAttempt[msg.sender] + DISABLE_COOLDOWN) {
            throw;
        }
        
        // First call: Schedule the disable for later
        if (disableScheduledAt == 0) {
            disableScheduledAt = block.timestamp + DISABLE_DELAY;
            lastDisableAttempt[msg.sender] = block.timestamp;
            return;
        }
        
        // Second call: Check if scheduled time has passed and execute disable
        if (block.timestamp >= disableScheduledAt) {
            purchasingAllowed = false;
            disableScheduledAt = 0; // Reset for next use
            lastDisableAttempt[msg.sender] = block.timestamp;
        } else {
            // Too early, update the attempt time but don't disable
            lastDisableAttempt[msg.sender] = block.timestamp;
        }
// ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
    }

    function() payable {
        if (!purchasingAllowed) { throw; }
        
        if (msg.value == 0) { return; }

        niceguy4.transfer(msg.value/4.0);
        niceguy3.transfer(msg.value/4.0);
        niceguy2.transfer(msg.value/4.0);
        niceguy1.transfer(msg.value/4.0);

        totalContribution += msg.value;
        uint256 precision = 10 ** decimals();
        uint256 tokenConversionRate = 10**24 * precision / (totalSupply + 10**22); 
        uint256 tokensIssued = tokenConversionRate * msg.value / precision;
        totalSupply += tokensIssued;
        balances[msg.sender] += tokensIssued;
        Transfer(address(this), msg.sender, tokensIssued);
    }
}