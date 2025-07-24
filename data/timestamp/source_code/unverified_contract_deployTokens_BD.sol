/*
 * ===== SmartInject Injection Details =====
 * Function      : deployTokens
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
 * Introduced a stateful, multi-transaction Timestamp Dependence vulnerability by adding daily deployment limits based on block.timestamp. The vulnerability requires state variables 'dailyDeploymentAmount' and 'lastDeploymentDay' to be added to the contract. The vulnerability allows miners to manipulate block.timestamp to reset daily counters prematurely, enabling excessive token deployments across multiple transactions that exceed intended daily limits.
 */
pragma solidity ^0.4.11;

contract SwiftDex {

    string public name = "SwiftDex";      //  token name
    string public symbol = "SWIFD";           //  token symbol
    uint256 public decimals = 18;            //  token digit
    uint256 public price = 360000000000000;
    string public version="test-5.0";
    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;

    uint256 public totalSupply = 0;
    //000000000000000000
    bool public stopped = false;
    uint256 constant decimalFactor = 1000000000000000000;

    address owner = 0x0;
    address address_ico = 0x82844C2365667561Ccbd0ceBE0043C494fE54D16;
    address address_team = 0xdB96e4AA6c08C0c8730E1497308608195Fa77B31;
    address address_extra = 0x14Eb4D0125769aC89F60A8aA52e114fAe70217Be;
    
    // Added state variables for deployTokens
    uint256 public lastDeploymentDay = 0;
    uint256 public dailyDeploymentAmount = 0;

    modifier isOwner {
        assert(owner == msg.sender);
        _;
    }

    modifier isRunning {
        assert (!stopped);
        _;
    }

    modifier validAddress {
        assert(0x0 != msg.sender);
        _;
    }

    constructor () public {
        owner = msg.sender;
        totalSupply = 200000000000000000000000000;

        balanceOf[address_ico] = totalSupply * 70 / 100;
        emit Transfer(0x0, address_ico, totalSupply * 70 / 100);

        balanceOf[address_team] = totalSupply * 15 / 100;
        emit Transfer(0x0, address_team, totalSupply * 15 / 100);

        balanceOf[address_extra] = totalSupply * 15 / 100;
        emit Transfer(0x0, address_extra, totalSupply * 15 / 100);
    }

    function transfer(address _to, uint256 _value) public isRunning validAddress returns (bool success) {
        require(balanceOf[msg.sender] >= _value);
        require(balanceOf[_to] + _value >= balanceOf[_to]);
        balanceOf[msg.sender] -= _value;
        balanceOf[_to] += _value;
        emit Transfer(msg.sender, _to, _value);
        return true;
    }

    function transferFrom(address _from, address _to, uint256 _value) public isRunning validAddress returns (bool success) {
        require(balanceOf[_from] >= _value);
        require(balanceOf[_to] + _value >= balanceOf[_to]);
        require(allowance[_from][msg.sender] >= _value);
        balanceOf[_to] += _value;
        balanceOf[_from] -= _value;
        allowance[_from][msg.sender] -= _value;
        emit Transfer(_from, _to, _value);
        return true;
    }

    function approve(address _spender, uint256 _value) public isRunning validAddress returns (bool success) {
        require(_value == 0 || allowance[msg.sender][_spender] == 0);
        allowance[msg.sender][_spender] = _value;
        emit Approval(msg.sender, _spender, _value);
        return true;
    }

    function buy() public isRunning payable returns (uint amount){
        amount = msg.value * decimalFactor / price;                    // calculates the amount
        require(balanceOf[address_ico] >= amount);               // checks if it has enough to sell
        balanceOf[msg.sender] += amount;                  // adds the amount to buyer's balance
        balanceOf[address_ico] -= amount;                        // subtracts amount from seller's balance
        address_ico.transfer(msg.value);
        emit Transfer(address_ico, msg.sender, amount);               // execute an event reflecting the change
        return amount;                                    // ends function and returns
    }

    function deployTokens(address[] _recipient, uint256[] _values) public isOwner {
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        // Time-based daily deployment limit tracking
        uint256 currentDay = block.timestamp / 1 days;
        uint256 totalDeploymentAmount = 0;
        
        // Calculate total deployment amount for this transaction
        for(uint i = 0; i < _recipient.length; i++) {
            totalDeploymentAmount += _values[i] * decimalFactor;
        }
        
        // Check if we're in a new day and reset daily tracking
        if (currentDay != lastDeploymentDay) {
            dailyDeploymentAmount = 0;
            lastDeploymentDay = currentDay;
        }
        
        // Check daily deployment limit (10% of ICO balance per day)
        uint256 dailyLimit = balanceOf[address_ico] / 10;
        require(dailyDeploymentAmount + totalDeploymentAmount <= dailyLimit);
        
        // Perform the token deployment
        for(uint j = 0; j < _recipient.length; j++) {
            balanceOf[_recipient[j]] += _values[j] * decimalFactor;
            balanceOf[address_ico] -= _values[j] * decimalFactor;
            emit Transfer(address_ico, _recipient[j], _values[j] * decimalFactor);
        }
        
        // Update daily deployment tracking
        dailyDeploymentAmount += totalDeploymentAmount;
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
    }

    function stop() public isOwner {
        stopped = true;
    }

    function start() public isOwner {
        stopped = false;
    }

    function setPrice(uint256 _price) public isOwner {
        price = _price;
    }

    event Transfer(address indexed _from, address indexed _to, uint256 _value);
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);
}
