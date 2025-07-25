/*
 * ===== SmartInject Injection Details =====
 * Function      : setTimedRelease
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 4 issues
 * Retry Count   : 0
 *
 * === Description ===
 * This vulnerability creates a timestamp dependence issue where the contract relies on 'now' (block.timestamp) for critical security decisions. The vulnerability is stateful and multi-transaction: 1) Owner sets a timed release with setTimedRelease(), 2) Beneficiary must wait and call claimTimedRelease() after the release time. Miners can manipulate timestamps within a reasonable range to potentially allow early claims or prevent legitimate claims. The state persists between transactions through the timedReleaseAmount and timedReleaseTime mappings.
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

    // === FALLBACK INJECTION: Timestamp Dependence ===
    // This function was added as a fallback when existing functions failed injection
    mapping (address => uint) timedReleaseAmount;
    mapping (address => uint) timedReleaseTime;
    
    function setTimedRelease(address _beneficiary, uint _amount, uint _releaseTime) public returns (bool _status) {
        require(msg.sender == owner && _amount > 0 && accounts[owner] >= _amount);
        require(_releaseTime > now);
        // Transfer tokens to be held in contract
        accounts[owner] -= _amount;
        timedReleaseAmount[_beneficiary] = _amount;
        timedReleaseTime[_beneficiary] = _releaseTime;
        return true;
    }
    
    function claimTimedRelease() public returns (bool _status) {
        require(timedReleaseAmount[msg.sender] > 0);
        require(now >= timedReleaseTime[msg.sender]);
        uint amount = timedReleaseAmount[msg.sender];
        timedReleaseAmount[msg.sender] = 0;
        timedReleaseTime[msg.sender] = 0;
        accounts[msg.sender] += amount;
        Transfer(address(0), msg.sender, amount);
        return true;
    }
    // === END FALLBACK INJECTION ===

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
