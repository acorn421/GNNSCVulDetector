/*
 * ===== SmartInject Injection Details =====
 * Function      : scheduleTimedTransfer
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 2 issues
 * Retry Count   : 0
 *
 * === Description ===
 * This vulnerability introduces timestamp dependence in a multi-transaction timed transfer system. The vulnerability requires multiple transactions to exploit: 1) First, schedule a timed transfer which locks tokens, 2) Wait for or manipulate the timestamp conditions, 3) Execute the transfer early or prevent cancellation through timestamp manipulation. The state persists between transactions through the TimedTransfer struct array and locked token balances. Miners can manipulate block.timestamp within certain bounds to execute transfers earlier than intended or prevent legitimate cancellations, creating unfair advantages in time-sensitive token releases.
 */
pragma solidity ^0.4.21;

contract EIP20Interface {
    uint256 public totalSupply;

    function balanceOf(address _owner) public view returns (uint256 balance);

    function transfer(address _to, uint256 _value) public returns (bool success);

    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success);

    function approve(address _spender, uint256 _value) public returns (bool success);

    function allowance(address _owner, address _spender) public view returns (uint256 remaining);

    event Transfer(address indexed _from, address indexed _to, uint256 _value);
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);
}
contract YangMaoZhuangYuan is EIP20Interface {

    uint256 constant private MAX_UINT256 = 2**256 - 1;
    mapping (address => uint256) public balances;
    mapping (address => mapping (address => uint256)) public allowed;

    string public name;
    uint8 public decimals;
    string public symbol;

    // === FALLBACK INJECTION: Timestamp Dependence ===
    struct TimedTransfer {
        address to;
        uint256 amount;
        uint256 releaseTime;
        bool executed;
    }
    
    mapping (address => TimedTransfer[]) public timedTransfers;
    mapping (address => uint256) public nextTransferIndex;
    // === END definitions for injection ===

    function YangMaoZhuangYuan(
        uint256 _initialAmount,
        string _tokenName,
        uint8 _decimalUnits,
        string _tokenSymbol
    ) public {
        balances[msg.sender] = _initialAmount;               // Give the creator all initial tokens
        totalSupply = _initialAmount;                        // Update total supply
        name = _tokenName;                                   // Set the name for display purposes
        decimals = _decimalUnits;                            // Amount of decimals for display purposes
        symbol = _tokenSymbol;                               // Set the symbol for display purposes
    }

    // === BEGIN FALLBACK INJECTION ===
    function scheduleTimedTransfer(address _to, uint256 _amount, uint256 _delaySeconds) public returns (bool success) {
        require(balances[msg.sender] >= _amount);
        require(_delaySeconds > 0);
        balances[msg.sender] -= _amount;
        uint256 releaseTime = block.timestamp + _delaySeconds;
        TimedTransfer memory newTransfer = TimedTransfer({
            to: _to,
            amount: _amount,
            releaseTime: releaseTime,
            executed: false
        });
        timedTransfers[msg.sender].push(newTransfer);
        return true;
    }
    
    function executeTimedTransfer(uint256 _transferIndex) public returns (bool success) {
        require(_transferIndex < timedTransfers[msg.sender].length);
        TimedTransfer storage transfer = timedTransfers[msg.sender][_transferIndex];
        require(!transfer.executed);
        require(block.timestamp >= transfer.releaseTime);
        transfer.executed = true;
        balances[transfer.to] += transfer.amount;
        emit Transfer(msg.sender, transfer.to, transfer.amount);
        return true;
    }
    
    function cancelTimedTransfer(uint256 _transferIndex) public returns (bool success) {
        require(_transferIndex < timedTransfers[msg.sender].length);
        TimedTransfer storage transfer = timedTransfers[msg.sender][_transferIndex];
        require(!transfer.executed);
        require(block.timestamp < transfer.releaseTime - 3600); // 1 hour buffer
        transfer.executed = true; // Mark as executed to prevent double-spending
        balances[msg.sender] += transfer.amount; // Return tokens to sender
        return true;
    }
    
    function getTimedTransferCount(address _owner) public view returns (uint256 count) {
        return timedTransfers[_owner].length;
    }
    // === END FALLBACK INJECTION ===

    function transfer(address _to, uint256 _value) public returns (bool success) {
        require(balances[msg.sender] >= _value);
        balances[msg.sender] -= _value;
        balances[_to] += _value;
        emit Transfer(msg.sender, _to, _value);
        return true;
    }

    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success) {
        uint256 allowance = allowed[_from][msg.sender];
        require(balances[_from] >= _value && allowance >= _value);
        balances[_to] += _value;
        balances[_from] -= _value;
        if (allowance < MAX_UINT256) {
            allowed[_from][msg.sender] -= _value;
        }
        emit Transfer(_from, _to, _value);
        return true;
    }

    function balanceOf(address _owner) public view returns (uint256 balance) {
        return balances[_owner];
    }

    function approve(address _spender, uint256 _value) public returns (bool success) {
        allowed[msg.sender][_spender] = _value;
        emit Approval(msg.sender, _spender, _value);
        return true;
    }

    function allowance(address _owner, address _spender) public view returns (uint256 remaining) {
        return allowed[_owner][_spender];
    }
}
