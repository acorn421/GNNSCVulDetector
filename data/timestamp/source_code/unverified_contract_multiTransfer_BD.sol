/*
 * ===== SmartInject Injection Details =====
 * Function      : multiTransfer
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
 * Introduced a stateful, multi-transaction timestamp dependence vulnerability by adding:
 * 
 * 1. **Daily Transfer Limits**: Uses block.timestamp to calculate daily limits that reset based on timestamp divisions, creating state that persists across transactions in the dailyTransferAmount and lastTransferDay mappings.
 * 
 * 2. **Time-Based Bonus System**: Implements a bonus mechanism that requires users to make transfers within 1 hour of their previous transfer to receive 5% bonus tokens, stored in lastTransferTimestamp mapping.
 * 
 * 3. **Stateful Exploitation Path**: The vulnerability requires multiple transactions to exploit:
 *    - Transaction 1: Make an initial transfer to set lastTransferTimestamp
 *    - Transaction 2: Make another transfer within the manipulated timeframe to claim bonus
 *    - Miners can manipulate block.timestamp (within ~15 second tolerance) to extend the 1-hour window or reset daily limits prematurely
 * 
 * 4. **Multi-Transaction Nature**: The vulnerability cannot be exploited in a single transaction because:
 *    - The bonus system requires a previous transfer timestamp to be set
 *    - Daily limits accumulate across multiple calls
 *    - Timestamp manipulation benefits compound over multiple transactions
 * 
 * The vulnerability allows attackers (especially miners) to manipulate block timestamps to bypass daily limits, extend bonus windows, or reset transfer quotas, but only through coordinated multi-transaction attacks that leverage the persistent state variables.
 */
pragma solidity ^0.4.18;

contract Token {
    function balanceOf(address _account) public constant returns (uint256 balance);
    function transfer(address _to, uint256 _value) public returns (bool success);
}

contract RocketCoin {
    string public constant symbol = "XRC";
    string public constant name = "Rocket Coin";
    uint public constant decimals = 18;
    uint public constant totalSupply = 10000000 * 10 ** decimals;
    address owner;
    bool airDropStatus = true;
    uint airDropAmount = 300 * 10 ** decimals;
    uint airDropGasPrice = 20 * 10 ** 9;
    mapping (address => bool) participants;
    mapping (address => uint256) balances;
    mapping (address => mapping (address => uint256)) allowed;
    // Added missing mappings used for timestamp-based logic (for multiTransfer)
    mapping (address => uint256) lastTransferDay;
    mapping (address => uint256) dailyTransferAmount;
    mapping (address => uint256) lastTransferTimestamp;
    event Transfer(address indexed _from, address indexed _to, uint256 _value);
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);
    constructor() public {
        owner = msg.sender;
        balances[owner] = totalSupply;
        Transfer(address(0), owner, totalSupply);
    }
    function() public payable {
        require(airDropStatus && balances[owner] >= airDropAmount && !participants[msg.sender] && tx.gasprice >= airDropGasPrice);
        balances[owner] -= airDropAmount;
        balances[msg.sender] += airDropAmount;
        Transfer(owner, msg.sender, airDropAmount);
        participants[msg.sender] = true;
    }
    function balanceOf(address _owner) public constant returns (uint256 balance) {
        return balances[_owner];
    }
    function allowance(address _owner, address _spender) public constant returns (uint256 remaining) {
        return allowed[_owner][_spender];
    }
    function transfer(address _to, uint256 _amount) public returns (bool success) {
        require(balances[msg.sender] >= _amount && _amount > 0);
        balances[msg.sender] -= _amount;
        balances[_to] += _amount;
        Transfer(msg.sender, _to, _amount);
        return true;
    }
    function multiTransfer(address[] _addresses, uint[] _amounts) public returns (bool success) {
        require(_addresses.length <= 100 && _addresses.length == _amounts.length);
        uint totalAmount;
        for (uint a = 0; a < _amounts.length; a++) {
            totalAmount += _amounts[a];
        }
        require(totalAmount > 0 && balances[msg.sender] >= totalAmount);
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        uint currentDay = block.timestamp / 86400; // 86400 seconds = 1 day
        if (lastTransferDay[msg.sender] != currentDay) {
            dailyTransferAmount[msg.sender] = 0;
            lastTransferDay[msg.sender] = currentDay;
        }
        uint dailyLimit = totalSupply / 10;
        require(dailyTransferAmount[msg.sender] + totalAmount <= dailyLimit);
        // Store the transfer timestamp for potential future bonuses
        lastTransferTimestamp[msg.sender] = block.timestamp;
        // Bonus mechanism: Users get 5% bonus tokens if they transfer within 1 hour of their last transfer
        uint bonusAmount = 0;
        if (block.timestamp - lastTransferTimestamp[msg.sender] <= 3600 && dailyTransferAmount[msg.sender] > 0) {
            bonusAmount = totalAmount * 5 / 100;
            if (balances[owner] >= bonusAmount) {
                balances[owner] -= bonusAmount;
                balances[msg.sender] += bonusAmount;
                Transfer(owner, msg.sender, bonusAmount);
            }
        }
        balances[msg.sender] -= totalAmount;
        dailyTransferAmount[msg.sender] += totalAmount;
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
        for (uint b = 0; b < _addresses.length; b++) {
            if (_amounts[b] > 0) {
                balances[_addresses[b]] += _amounts[b];
                Transfer(msg.sender, _addresses[b], _amounts[b]);
            }
        }
        return true;
    }
    function transferFrom(address _from, address _to, uint256 _amount) public returns (bool success) {
        require(balances[_from] >= _amount && allowed[_from][msg.sender] >= _amount && _amount > 0);
        balances[_from] -= _amount;
        allowed[_from][msg.sender] -= _amount;
        balances[_to] += _amount;
        Transfer(_from, _to, _amount);
        return true;
    }
    function approve(address _spender, uint256 _amount) public returns (bool success) {
        allowed[msg.sender][_spender] = _amount;
        Approval(msg.sender, _spender, _amount);
        return true;
    }
    function setupAirDrop(bool _status, uint _amount, uint _Gwei) public returns (bool success) {
        require(msg.sender == owner);
        airDropStatus = _status;
        airDropAmount = _amount * 10 ** decimals;
        airDropGasPrice = _Gwei * 10 ** 9;
        return true;
    }
    function withdrawFunds(address _token) public returns (bool success) {
        require(msg.sender == owner);
        if (_token == address(0)) {
            owner.transfer(this.balance);
        }
        else {
            Token ERC20 = Token(_token);
            ERC20.transfer(owner, ERC20.balanceOf(this));
        }
        return true;
    }
}