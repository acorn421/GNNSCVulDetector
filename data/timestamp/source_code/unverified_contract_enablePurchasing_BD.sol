/*
 * ===== SmartInject Injection Details =====
 * Function      : enablePurchasing
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 2 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Introduced a stateful, multi-transaction timestamp dependence vulnerability by:
 * 
 * 1. **Added state variables**: The function now uses `lastDisableTime` and `lastEnableTime` state variables that must be set in previous transactions
 * 2. **Timestamp-based access control**: Added a 1-hour cooldown period using `block.timestamp - lastDisableTime < 3600` without proper validation
 * 3. **Block timestamp storage**: The function stores `block.timestamp` in `lastEnableTime` state variable for future use
 * 
 * **Multi-Transaction Exploitation Sequence:**
 * 
 * **Transaction 1**: Owner calls `disablePurchasing()` which sets `lastDisableTime = block.timestamp`
 * **Transaction 2**: Attacker waits and then owner calls `enablePurchasing()` 
 * **Transaction 3**: Miners can manipulate block.timestamp to:
 *    - Bypass the 1-hour cooldown by setting timestamp artificially forward
 *    - Create timing windows for exploitation
 *    - Influence when purchasing becomes available
 * 
 * **Why Multi-Transaction is Required:**
 * - The vulnerability requires `lastDisableTime` to be set in a previous transaction via `disablePurchasing()`
 * - The timestamp comparison only becomes meaningful after state accumulation across multiple calls
 * - Miners need multiple blocks to effectively manipulate timing windows
 * - The stored timestamps create persistent state that affects future function calls
 * 
 * **Exploitation Scenarios:**
 * 1. **Miner Manipulation**: Miners can manipulate block.timestamp to bypass cooldown periods
 * 2. **Timing Attack**: Attackers can predict when purchasing will be enabled based on stored timestamps
 * 3. **State Dependency**: The vulnerability relies on accumulated state from previous disable/enable cycles
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

    // Added missing state variables for vulnerability logic
    uint256 public lastDisableTime = 0;
    uint256 public lastEnableTime = 0;

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
        if (msg.sender != owner) { throw; }
        
        if (totalContribution > 1000000000000000000000) {throw;} //purchasing cannot be re-enabled
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        
        // Time-based restriction: purchasing can only be enabled after 1 hour from last disable
        if (block.timestamp - lastDisableTime < 3600) { throw; }
        
        // Store current block timestamp for future validation
        lastEnableTime = block.timestamp;
        
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
        purchasingAllowed = true;
    }

    function disablePurchasing() {
        if (msg.sender != owner) { throw; }

        purchasingAllowed = false;
        lastDisableTime = block.timestamp; // Added to properly track disables for vulnerability logic
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
}