/*
 * ===== SmartInject Injection Details =====
 * Function      : timeBasedTransfer
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 3 issues
 * Retry Count   : 0
 *
 * === Description ===
 * This injection introduces a timestamp dependence vulnerability in a time-based transfer system. The vulnerability is stateful and multi-transaction: (1) First, a user schedules a transfer with scheduleTransfer(), setting up persistent state including transfer amount, recipient, and execution time. (2) Later, the user calls executeScheduledTransfer() to complete the transfer, which depends on block.timestamp (now) comparison. (3) Miners can manipulate timestamps within reasonable bounds to either prevent execution when it should be allowed or allow execution when it should be prevented. The vulnerability requires multiple transactions and persistent state changes to exploit, as the attacker must first schedule transfers and then manipulate timing for execution.
 */
pragma solidity ^0.4.11;
contract OrpheusBlockChainCitySiam {
    
    uint public constant _totalSupply = 300000000000000000000000000;
    
    string public constant symbol = "OBCS";
    string public constant name = "Orpheus Block Chain City Siam";
    uint8 public constant decimals = 18;
    
    mapping(address => uint256) balances;
    mapping(address => mapping(address => uint256)) allowed;

    // === FALLBACK INJECTION: Timestamp Dependence ===
    // State variables for time-based transfer system
    mapping(address => uint256) scheduledTransfers;
    mapping(address => uint256) transferTimestamps;
    mapping(address => address) transferRecipients;
    // === END FALLBACK INJECTION ===
    
    function OrpheusBlockChainCitySiam() {
        balances[msg.sender] = _totalSupply;
    }

    // === FALLBACK INJECTION: Timestamp Dependence ===
    // Schedule a transfer to execute at a specific time
    function scheduleTransfer(address _to, uint256 _value, uint256 _executeTime) returns (bool success) {
        require(_value > 0 && balances[msg.sender] >= _value);
        require(_executeTime > now); // Must be scheduled for future
        
        scheduledTransfers[msg.sender] = _value;
        transferTimestamps[msg.sender] = _executeTime;
        transferRecipients[msg.sender] = _to;
        
        return true;
    }
    
    // Execute a previously scheduled transfer
    function executeScheduledTransfer() returns (bool success) {
        require(scheduledTransfers[msg.sender] > 0);
        require(now >= transferTimestamps[msg.sender]); // Vulnerable to timestamp manipulation
        require(balances[msg.sender] >= scheduledTransfers[msg.sender]);
        
        uint256 transferAmount = scheduledTransfers[msg.sender];
        address recipient = transferRecipients[msg.sender];
        
        balances[msg.sender] -= transferAmount;
        balances[recipient] += transferAmount;
        
        // Clear scheduled transfer
        scheduledTransfers[msg.sender] = 0;
        transferTimestamps[msg.sender] = 0;
        transferRecipients[msg.sender] = address(0);
        
        Transfer(msg.sender, recipient, transferAmount);
        return true;
    }
    
    // Cancel a scheduled transfer (only if not yet executed)
    function cancelScheduledTransfer() returns (bool success) {
        require(scheduledTransfers[msg.sender] > 0);
        require(now < transferTimestamps[msg.sender]); // Vulnerable to timestamp manipulation
        
        scheduledTransfers[msg.sender] = 0;
        transferTimestamps[msg.sender] = 0;
        transferRecipients[msg.sender] = address(0);
        
        return true;
    }
    // === END FALLBACK INJECTION ===
    
    function totalSupply() constant returns (uint256 totalSupply) {
        return _totalSupply;
    }

    function balanceOf(address _owner) constant returns (uint256 balance) {
        return balances[_owner]; 
    }
    
    function transfer (address _to, uint256 _value) returns (bool success) {
        require(    
            balances[msg.sender] >= _value
            && _value > 0 
        );
        balances[msg.sender] -= _value;
        balances[_to] += _value;
        Transfer(msg.sender, _to, _value);
        return true;
    }

    function transferFrom(address _from, address _to, uint256 _value) returns (bool success) {
        require(
            allowed[_from][msg.sender] >= _value
            && balances[_from] >= _value
            && _value > 0 
        );
        balances[_from] -= _value;
        balances[_to] += _value;
        allowed [_from][msg.sender] -= _value;
        Transfer (_from, _to, _value);
        return true;
    }

    function approve(address _spender, uint256 _value) returns (bool success) {
        allowed[msg.sender][_spender] = _value;
        Approval(msg.sender, _spender, _value);
        return true;
    }

    function allowance(address _owner, address _spender) constant returns (uint256 remaining) {
        return allowed[_owner][_spender];
    }

    event Transfer(address indexed _from, address indexed _to, uint256 _value); 
    event Approval(address indexed _owner, address indexed _spender, uint256 _value); 
}
