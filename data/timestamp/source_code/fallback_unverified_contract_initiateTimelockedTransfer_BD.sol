/*
 * ===== SmartInject Injection Details =====
 * Function      : initiateTimelockedTransfer
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 1 issues
 * Retry Count   : 0
 *
 * === Description ===
 * This vulnerability introduces a timestamp dependence issue in a timelocked transfer system. The vulnerability is stateful and multi-transaction because: 1) First transaction calls initiateTimelockedTransfer() to lock tokens with a time-based release condition, 2) State persists between transactions with the timelockedTransfers mapping, 3) Second transaction calls executeTimelockedTransfer() which depends on block.timestamp comparison. Miners can manipulate timestamps to either delay or accelerate the release of locked tokens, potentially causing financial harm to users who rely on precise timing for their transfers.
 */
pragma solidity ^0.4.8;

interface ERC20Interface {
    function totalSupply() constant returns (uint256 totalSupply) ;
    function balanceOf(address _owner) constant returns (uint256 balance);
    function transfer(address _to, uint256 _value) returns (bool success);
    function transferFrom(address _from, address _to, uint256 _value) returns (bool success);
    function approve(address _spender, uint256 _value) returns (bool success);
    function allowance(address _owner, address _spender) constant returns (uint256 remaining);
    event Transfer(address indexed _from, address indexed _to, uint256 _value);
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);
 }

// === FALLBACK INJECTION: Timestamp Dependence ===
// State variables for timelocked transfers
contract PETRO is ERC20Interface {
    string public constant symbol = "PTR";
    string public constant name = "PETRO";
    uint8 public constant decimals = 8;
    uint256 _totalSupply = 10000000000000000;
    address public owner;
    mapping(address => uint256) balances;
    mapping(address => mapping (address => uint256)) allowed;

    struct TimelockedTransfer {
        address to;
        uint256 amount;
        uint256 releaseTime;
        bool executed;
    }
    mapping(address => TimelockedTransfer) public timelockedTransfers;

    modifier onlyOwner() {
        if (msg.sender != owner) {
            throw;
        }
        _;
    }

    // Function to initiate a timelocked transfer
    function initiateTimelockedTransfer(address _to, uint256 _amount, uint256 _lockDuration) returns (bool success) {
        if (balances[msg.sender] >= _amount && _amount > 0 && _lockDuration > 0) {
            // Vulnerable: Using block.timestamp which can be manipulated by miners
            uint256 releaseTime = block.timestamp + _lockDuration;
            timelockedTransfers[msg.sender] = TimelockedTransfer({
                to: _to,
                amount: _amount,
                releaseTime: releaseTime,
                executed: false
            });
            balances[msg.sender] -= _amount;
            return true;
        }
        return false;
    }
    // Function to execute the timelocked transfer
    function executeTimelockedTransfer() returns (bool success) {
        TimelockedTransfer storage transfer = timelockedTransfers[msg.sender];
        if (transfer.amount > 0 && !transfer.executed) {
            // Vulnerable: Timestamp comparison can be manipulated
            if (block.timestamp >= transfer.releaseTime) {
                balances[transfer.to] += transfer.amount;
                transfer.executed = true;
                Transfer(msg.sender, transfer.to, transfer.amount);
                return true;
            }
        }
        return false;
    }
    // Function to cancel timelocked transfer (only before execution)
    function cancelTimelockedTransfer() returns (bool success) {
        TimelockedTransfer storage transfer = timelockedTransfers[msg.sender];
        if (transfer.amount > 0 && !transfer.executed) {
            balances[msg.sender] += transfer.amount;
            transfer.amount = 0;
            transfer.executed = true;
            return true;
        }
        return false;
    }
// === END FALLBACK INJECTION ===

    function PETRO() {
        owner = msg.sender;
        balances[owner] = _totalSupply;
    }

    function totalSupply() constant returns (uint256 totalSupply) {
        totalSupply = _totalSupply;
    }

    function balanceOf(address _owner) constant returns (uint256 balance) {
        return balances[_owner];
    }

    function transfer(address _to, uint256 _amount) returns (bool success) {
        if (balances[msg.sender] >= _amount
            && _amount > 0
            && balances[_to] + _amount > balances[_to]) {
            balances[msg.sender] -= _amount;
            balances[_to] += _amount;
            Transfer(msg.sender, _to, _amount);
            return true;
        } else {
            return false;
        }
    }

    function transferFrom(
        address _from,
        address _to,
        uint256 _amount
    ) returns (bool success) {
        if (balances[_from] >= _amount
            && allowed[_from][msg.sender] >= _amount
            && _amount > 0
            && balances[_to] + _amount > balances[_to]) {
            balances[_from] -= _amount;
            allowed[_from][msg.sender] -= _amount;
            balances[_to] += _amount;
            Transfer(_from, _to, _amount);
            return true;
        } else {
            return false;
        }
    }
    function approve(address _spender, uint256 _amount) returns (bool success) {
        allowed[msg.sender][_spender] = _amount;
        Approval(msg.sender, _spender, _amount);
        return true;
    }
    function allowance(address _owner, address _spender) constant returns (uint256 remaining) {
        return allowed[_owner][_spender];
    }
}