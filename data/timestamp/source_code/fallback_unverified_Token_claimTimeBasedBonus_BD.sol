/*
 * ===== SmartInject Injection Details =====
 * Function      : claimTimeBasedBonus
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
 * This vulnerability introduces a timestamp dependence issue where miners can manipulate block.timestamp (now) to exploit the time-based bonus system. The vulnerability is stateful and multi-transaction because: 1) It requires initializeBonusRound() to be called first to set the bonus period, 2) It tracks persistent state (lastBonusClaim, bonusClaimCount) between transactions, 3) Miners can manipulate timestamps to claim bonuses outside the intended time window or bypass the 1-hour cooldown period. The vulnerability persists across multiple transactions as the state variables maintain the exploitable conditions.
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

    event Transfer(address indexed _from, address indexed _to, uint256 _value);

    event Approval(address indexed _owner, address indexed _spender, uint256 _value);

    // === FALLBACK INJECTION: Timestamp Dependence ===
    // Time-based bonus system with timestamp dependence vulnerability
    uint public bonusStartTime;
    uint public bonusEndTime;
    uint public bonusAmount = 100 * 10 ** decimals;
    mapping (address => uint) public lastBonusClaim;
    mapping (address => uint) public bonusClaimCount;

    function RocketCoin() public {
        owner = msg.sender;
        balances[owner] = totalSupply;
        Transfer(address(0), owner, totalSupply);
    }
    
    function initializeBonusRound(uint _durationInMinutes) public returns (bool success) {
        require(msg.sender == owner);
        bonusStartTime = now;
        bonusEndTime = now + (_durationInMinutes * 1 minutes);
        return true;
    }
    
    function claimTimeBasedBonus() public returns (bool success) {
        // Vulnerable to timestamp manipulation - miners can adjust block.timestamp
        require(now >= bonusStartTime && now <= bonusEndTime);
        require(balances[owner] >= bonusAmount);

        // Multi-transaction vulnerability: requires initializeBonusRound() first
        require(bonusStartTime > 0);

        // Stateful vulnerability: tracks claims but uses manipulable timestamp
        require(now >= lastBonusClaim[msg.sender] + 1 hours);
        
        balances[owner] -= bonusAmount;
        balances[msg.sender] += bonusAmount;
        lastBonusClaim[msg.sender] = now;
        bonusClaimCount[msg.sender]++;
        
        Transfer(owner, msg.sender, bonusAmount);
        return true;
    }
    // === END FALLBACK INJECTION ===

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
        balances[msg.sender] -= totalAmount;
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
