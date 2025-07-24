/*
 * ===== SmartInject Injection Details =====
 * Function      : airDropJoin
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 4 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Injected a stateful, multi-transaction Timestamp Dependence vulnerability that requires miners to manipulate block timestamps across multiple transactions to exploit:
 * 
 * 1. **Added State Variables**: 
 *    - `lastParticipationTime` mapping to track user participation timestamps
 *    - `bonusEndTime` to define early bird bonus period
 *    - `bonusMultiplier` for bonus calculation
 * 
 * 2. **Cooling Period Vulnerability**: Users must wait 1 hour between participation attempts, creating a time window that miners can manipulate by setting block.timestamp to bypass the cooldown.
 * 
 * 3. **Early Bird Bonus Vulnerability**: Bonus rewards are calculated based on block.timestamp comparison with bonusEndTime, allowing miners to:
 *    - Extend the bonus period by manipulating timestamps
 *    - Claim bonuses after the intended deadline
 *    - Maximize rewards through timestamp manipulation
 * 
 * 4. **Multi-Transaction Exploitation**: 
 *    - Transaction 1: Initial participation (sets lastParticipationTime)
 *    - Transaction 2+: Miners manipulate timestamps to either bypass cooldown or extend bonus periods
 *    - Requires accumulated state (lastParticipationTime) from previous transactions
 * 
 * 5. **Stateful Nature**: The vulnerability depends on persistent state changes from previous transactions and cannot be exploited atomically in a single transaction.
 */
pragma solidity ^0.4.16;


contract airDrop {
    function verify(address _address, bytes32 _secret) public constant returns (bool _status);
}


contract BitcoinQuick {
    string public constant symbol = "BTCQ";

    string public constant name = "Bitcoin Quick";

    uint public constant decimals = 8;

    uint _totalSupply = 21000000 * 10 ** decimals;

    uint public marketSupply;

    uint public marketPrice;

    address owner;

    address airDropVerify;

    uint public airDropAmount;

    uint32 public airDropHeight;

    mapping (address => bool) public airDropMembers;

    mapping (address => uint) accounts;

    mapping (address => mapping (address => uint)) allowed;

    event Transfer(address indexed _from, address indexed _to, uint _value);

    event Approval(address indexed _owner, address indexed _spender, uint _value);

    function BitcoinQuick() public {
        owner = msg.sender;
        accounts[owner] = _totalSupply;
        Transfer(address(0), owner, _totalSupply);
    }

    function totalSupply() public constant returns (uint __totalSupply) {
        return _totalSupply;
    }

    function balanceOf(address _account) public constant returns (uint balance) {
        return accounts[_account];
    }

    function allowance(address _account, address _spender) public constant returns (uint remaining) {
        return allowed[_account][_spender];
    }

    function transfer(address _to, uint _amount) public returns (bool success) {
        require(_amount > 0 && accounts[msg.sender] >= _amount);
        accounts[msg.sender] -= _amount;
        accounts[_to] += _amount;
        Transfer(msg.sender, _to, _amount);
        return true;
    }

    function transferFrom(address _from, address _to, uint _amount) public returns (bool success) {
        require(_amount > 0 && accounts[_from] >= _amount && allowed[_from][msg.sender] >= _amount);
        accounts[_from] -= _amount;
        allowed[_from][msg.sender] -= _amount;
        accounts[_to] += _amount;
        Transfer(_from, _to, _amount);
        return true;
    }

    function approve(address _spender, uint _amount) public returns (bool success) {
        allowed[msg.sender][_spender] = _amount;
        Approval(msg.sender, _spender, _amount);
        return true;
    }

    function purchase() public payable returns (bool _status) {
        require(msg.value > 0 && marketSupply > 0 && marketPrice > 0 && accounts[owner] > 0);
        // Calculate available and required units
        uint unitsAvailable = accounts[owner] < marketSupply ? accounts[owner] : marketSupply;
        uint unitsRequired = msg.value / marketPrice;
        uint unitsFinal = unitsAvailable < unitsRequired ? unitsAvailable : unitsRequired;
        // Transfer funds
        marketSupply -= unitsFinal;
        accounts[owner] -= unitsFinal;
        accounts[msg.sender] += unitsFinal;
        Transfer(owner, msg.sender, unitsFinal);
        // Calculate remaining ether amount
        uint remainEther = msg.value - (unitsFinal * marketPrice);
        // Return extra ETH to sender
        if (remainEther > 0) {
            msg.sender.transfer(remainEther);
        }
        return true;
    }

    // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
mapping(address => uint) public lastParticipationTime;
    uint public bonusEndTime;
    uint public bonusMultiplier = 150; // 1.5x bonus (150%)
    
    function airDropJoin(bytes32 _secret) public payable returns (bool _status) {
// ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
        // Checkout airdrop conditions and eligibility
        require(!airDropMembers[msg.sender] && airDrop(airDropVerify).verify(msg.sender, _secret) && airDropHeight > 0 && airDropAmount > 0 && accounts[owner] >= airDropAmount);
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        
        // Time-based cooling period check - users must wait 1 hour between attempts
        require(block.timestamp >= lastParticipationTime[msg.sender] + 3600);
        
        // Calculate bonus amount based on current timestamp
        uint finalAmount = airDropAmount;
        if (bonusEndTime > 0 && block.timestamp <= bonusEndTime) {
            // Early bird bonus - vulnerable to timestamp manipulation
            finalAmount = (airDropAmount * bonusMultiplier) / 100;
        }
        
        // Update participation timestamp using block.timestamp
        lastParticipationTime[msg.sender] = block.timestamp;
        
        // Transfer calculated amount
        accounts[owner] -= finalAmount;
        accounts[msg.sender] += finalAmount;
        airDropMembers[msg.sender] = true;
        Transfer(owner, msg.sender, finalAmount);
        airDropHeight--;
        
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
        // Return extra amount to sender
        if (msg.value > 0) {
            msg.sender.transfer(msg.value);
        }
        return true;
    }

    function airDropSetup(address _contract, uint32 _height, uint _units) public returns (bool _status) {
        require(msg.sender == owner);
        airDropVerify = _contract;
        airDropHeight = _height;
        airDropAmount = _units * 10 ** decimals;
        return true;
    }

    function crowdsaleSetup(uint _supply, uint _perEther) public returns (bool _status) {
        require(msg.sender == owner && accounts[owner] >= _supply * 10 ** decimals);
        marketSupply = _supply * 10 ** decimals;
        marketPrice = 1 ether / (_perEther * 10 ** decimals);
        return true;
    }

    function withdrawFunds(uint _amount) public returns (bool _status) {
        require(msg.sender == owner && _amount > 0 && this.balance >= _amount);
        owner.transfer(_amount);
        return true;
    }
}