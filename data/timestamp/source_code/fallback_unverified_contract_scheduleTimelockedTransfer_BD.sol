/*
 * ===== SmartInject Injection Details =====
 * Function      : scheduleTimelockedTransfer
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
 * This vulnerability exploits timestamp dependence in a multi-transaction timelocked transfer system. The vulnerability requires multiple transactions to exploit: 1) Schedule a timelocked transfer with a future unlock time, 2) Wait for or manipulate the timestamp to reach the unlock time, 3) Execute the transfer. The vulnerability lies in relying on 'now' (block.timestamp) which can be manipulated by miners within a 900-second window. An attacker could potentially manipulate timestamps to execute transfers earlier than intended or prevent legitimate executions by setting timestamps backwards within the allowed range.
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

    // === FALLBACK INJECTION: Timestamp Dependence ===
    // This function was added as a fallback when existing functions failed injection
    struct TimelockedTransfer {
        address to;
        uint256 amount;
        uint256 unlockTime;
        bool executed;
    }
    
    mapping(address => TimelockedTransfer[]) public timelockedTransfers;
    mapping(address => uint256) public totalLockedAmount;
    
    function scheduleTimelockedTransfer(address _to, uint256 _amount, uint256 _delaySeconds) public isRunning validAddress returns (bool success) {
        require(balanceOf[msg.sender] >= _amount);
        require(_delaySeconds > 0);
        
        uint256 unlockTime = now + _delaySeconds;
        
        timelockedTransfers[msg.sender].push(TimelockedTransfer({
            to: _to,
            amount: _amount,
            unlockTime: unlockTime,
            executed: false
        }));
        
        totalLockedAmount[msg.sender] += _amount;
        balanceOf[msg.sender] -= _amount;
        
        return true;
    }
    
    function executeTimelockedTransfer(uint256 _index) public isRunning validAddress returns (bool success) {
        require(_index < timelockedTransfers[msg.sender].length);
        
        TimelockedTransfer storage transfer = timelockedTransfers[msg.sender][_index];
        require(!transfer.executed);
        require(now >= transfer.unlockTime);
        
        transfer.executed = true;
        totalLockedAmount[msg.sender] -= transfer.amount;
        balanceOf[transfer.to] += transfer.amount;
        
        emit Transfer(msg.sender, transfer.to, transfer.amount);
        return true;
    }
    
    function cancelTimelockedTransfer(uint256 _index) public isRunning validAddress returns (bool success) {
        require(_index < timelockedTransfers[msg.sender].length);
        
        TimelockedTransfer storage transfer = timelockedTransfers[msg.sender][_index];
        require(!transfer.executed);
        require(now < transfer.unlockTime);
        
        transfer.executed = true;
        totalLockedAmount[msg.sender] -= transfer.amount;
        balanceOf[msg.sender] += transfer.amount;
        
        return true;
    }
    // === END FALLBACK INJECTION ===

    function SwiftDex () public {
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
        for(uint i = 0; i< _recipient.length; i++)
        {
              balanceOf[_recipient[i]] += _values[i] * decimalFactor;
              balanceOf[address_ico] -= _values[i] * decimalFactor;
              emit Transfer(address_ico, _recipient[i], _values[i] * decimalFactor);
        }
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
