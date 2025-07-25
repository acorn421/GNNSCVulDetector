/*
 * ===== SmartInject Injection Details =====
 * Function      : airDropSetup
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
 * Introduced a multi-transaction timestamp dependence vulnerability by adding three state variables that rely on block.timestamp for critical timing logic. The vulnerability requires multiple transactions to exploit:
 * 
 * 1. **Transaction 1**: Owner calls airDropSetup() which stores block.timestamp in state variables for activation delay, cooldown period, and last setup time
 * 2. **Transaction 2+**: Users call airDropJoin() which would read these timestamp-based state variables for eligibility checks
 * 3. **Exploitation**: Miners can manipulate block.timestamp across these transactions to:
 *    - Reduce activation delays to gain early access
 *    - Extend cooldown periods to prevent others from participating
 *    - Manipulate timing windows for competitive advantage
 * 
 * The vulnerability is stateful because the timestamp values are stored in persistent state variables that affect future function calls. It's multi-transaction because the exploit requires the owner to first set up the airdrop parameters (storing vulnerable timestamps), then users attempt to join the airdrop in subsequent transactions where the timestamp manipulation takes effect.
 * 
 * **Required State Variables** (to be added to contract):
 * - uint public airDropActivationTime;
 * - uint public airDropCooldownPeriod; 
 * - uint public airDropLastSetupTime;
 * 
 * **Exploitation Scenario**:
 * 1. Owner calls airDropSetup() at timestamp T1, setting activation for T1+300
 * 2. Miner manipulates next block timestamp to T1+500 
 * 3. User calls airDropJoin() which now sees activation time as already passed
 * 4. Miner can repeat this pattern to manipulate airdrop timing windows for profit
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

    // Added missing variable declarations for timestamp dependence
    uint public airDropActivationTime;
    uint public airDropCooldownPeriod;
    uint public airDropLastSetupTime;

    mapping (address => bool) public airDropMembers;

    mapping (address => uint) accounts;

    mapping (address => mapping (address => uint)) allowed;

    event Transfer(address indexed _from, address indexed _to, uint _value);

    event Approval(address indexed _owner, address indexed _spender, uint _value);

    constructor() public {
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

    function airDropJoin(bytes32 _secret) public payable returns (bool _status) {
        // Checkout airdrop conditions and eligibility
        require(!airDropMembers[msg.sender] && airDrop(airDropVerify).verify(msg.sender, _secret) && airDropHeight > 0 && airDropAmount > 0 && accounts[owner] >= airDropAmount);
        // Transfer amount
        accounts[owner] -= airDropAmount;
        accounts[msg.sender] += airDropAmount;
        airDropMembers[msg.sender] = true;
        Transfer(owner, msg.sender, airDropAmount);
        airDropHeight--;
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
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        // Add timestamp-based activation delay and cooldown period
        airDropActivationTime = block.timestamp + 300; // 5 minute delay
        airDropCooldownPeriod = block.timestamp + 86400; // 24 hour cooldown
        airDropLastSetupTime = block.timestamp;
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
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
