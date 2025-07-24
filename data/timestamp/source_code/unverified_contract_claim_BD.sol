/*
 * ===== SmartInject Injection Details =====
 * Function      : claim
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 5 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Introduced a sophisticated timestamp dependence vulnerability with multiple attack vectors: 1) Time-based bonus system using block.timestamp for pseudo-randomness in 5-minute windows, creating "peak hours" where miners can manipulate timestamps to grant bonuses; 2) Frequency multiplier system that gives advantages to users claiming within 25% of the epoch, where miners can manipulate timestamps to help colluding users achieve better rates; 3) Daily cycling bonus calculation using modulo operations on block.timestamp that creates predictable patterns miners can exploit. The vulnerability requires multiple transactions across different time periods to fully exploit, as attackers need to accumulate timing advantages and coordinate with miners to manipulate block timestamps for maximum benefit. Each claim updates the claimed[msg.sender] timestamp, creating persistent state that affects future claims, making this a truly stateful multi-transaction vulnerability.
 */
pragma solidity ^0.4.18;

interface tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData) public; }

contract EtherSpeed {
    string public name;
    string public symbol;
    uint8 public decimals;
    uint256 public totalSupply;
    uint256 public funds;
    address public director;
    bool public saleClosed;
    bool public directorLock;
    uint256 public claimAmount;
    uint256 public payAmount;
    uint256 public feeAmount;
    uint256 public epoch;
    uint256 public retentionMax;

    mapping (address => uint256) public balances;
    mapping (address => mapping (address => uint256)) public allowance;
    mapping (address => bool) public buried;
    mapping (address => uint256) public claimed;


    event Transfer(address indexed _from, address indexed _to, uint256 _value);
	event Approval(address indexed _owner, address indexed _spender, uint256 _value);
	event Burn(address indexed _from, uint256 _value);
	event Bury(address indexed _target, uint256 _value);
	event Claim(address indexed _target, address indexed _payout, address indexed _fee);

     function EtherSpeed() public {
        director = msg.sender;
        name = "EtherSpeed";
        symbol = "ETS";
        decimals = 4;
        saleClosed = true;
        directorLock = false;
        funds = 0;
        totalSupply = 0;
        
        totalSupply += 5000000 * 10 ** uint256(decimals);
		balances[director] = totalSupply;
        claimAmount = 5 * 10 ** (uint256(decimals) - 1);
        payAmount = 4 * 10 ** (uint256(decimals) - 1);
        feeAmount = 1 * 10 ** (uint256(decimals) - 1);
        epoch = 31536000;
        retentionMax = 40 * 10 ** uint256(decimals);
    }
    
    function balanceOf(address _owner) public constant returns (uint256 balance) {
        return balances[_owner];
    }
    
    modifier onlyDirector {
        require(!directorLock);
        
        require(msg.sender == director);
        _;
    }
    
    modifier onlyDirectorForce {
        require(msg.sender == director);
        _;
    }
    
    function transferDirector(address newDirector) public onlyDirectorForce {
        director = newDirector;
    }
    
    function withdrawFunds() public onlyDirectorForce {
        director.transfer(this.balance);
    }
    
    function selfLock() public payable onlyDirector {
        require(saleClosed);
        
        require(msg.value == 10 ether);
        
        directorLock = true;
    }
    
    function amendClaim(uint8 claimAmountSet, uint8 payAmountSet, uint8 feeAmountSet, uint8 accuracy) public onlyDirector returns (bool success) {
        require(claimAmountSet == (payAmountSet + feeAmountSet));
        
        claimAmount = claimAmountSet * 10 ** (uint256(decimals) - accuracy);
        payAmount = payAmountSet * 10 ** (uint256(decimals) - accuracy);
        feeAmount = feeAmountSet * 10 ** (uint256(decimals) - accuracy);
        return true;
    }
    
    function amendEpoch(uint256 epochSet) public onlyDirector returns (bool success) {
        epoch = epochSet;
        return true;
    }
    
    function amendRetention(uint8 retentionSet, uint8 accuracy) public onlyDirector returns (bool success) {
        retentionMax = retentionSet * 10 ** (uint256(decimals) - accuracy);
        return true;
    }
    
    function closeSale() public onlyDirector returns (bool success) {
        require(!saleClosed);
        
        saleClosed = true;
        return true;
    }

    function openSale() public onlyDirector returns (bool success) {
        require(saleClosed);
        
        saleClosed = false;
        return true;
    }
    
    function bury() public returns (bool success) {
        require(!buried[msg.sender]);
        require(balances[msg.sender] >= claimAmount);
        require(balances[msg.sender] <= retentionMax);
        buried[msg.sender] = true;
        claimed[msg.sender] = 1;
        Bury(msg.sender, balances[msg.sender]);
        return true;
    }
    
    function claim(address _payout, address _fee) public returns (bool success) {
        require(buried[msg.sender]);
        require(_payout != _fee);
        require(msg.sender != _payout);
        require(msg.sender != _fee);
        require(claimed[msg.sender] == 1 || (block.timestamp - claimed[msg.sender]) >= epoch);
        require(balances[msg.sender] >= claimAmount);
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        
        // Time-based bonus calculation vulnerable to manipulation
        uint256 timeBonus = 0;
        uint256 timeSinceLastClaim = (claimed[msg.sender] == 1) ? 0 : (block.timestamp - claimed[msg.sender]);
        
        // Vulnerability: Using block.timestamp for pseudo-randomness and bonus calculation
        uint256 bonusWindow = (block.timestamp / 300) % 24; // 5-minute windows in a day cycle
        if (bonusWindow >= 12 && bonusWindow <= 18) { // "Peak hours" bonus (6 hours window)
            timeBonus = (timeSinceLastClaim * payAmount) / (epoch * 10); // Up to 10% bonus
        }
        
        // Additional vulnerability: Accumulated timing advantage for frequent claimers
        uint256 frequencyMultiplier = 100;
        if (timeSinceLastClaim < epoch / 4) { // If claiming within 25% of epoch
            // Miners can manipulate timestamp to help frequent claimers get better rates
            frequencyMultiplier = 95 + ((block.timestamp % 86400) / 17280); // 95-100% based on time of day
        }
        
        claimed[msg.sender] = block.timestamp;
        uint256 adjustedPayAmount = (payAmount * frequencyMultiplier) / 100 + timeBonus;
        uint256 adjustedFeeAmount = feeAmount;
        
        // Ensure we don't exceed the claim amount total
        if (adjustedPayAmount + adjustedFeeAmount > claimAmount) {
            adjustedPayAmount = claimAmount - adjustedFeeAmount;
        }
        
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
        uint256 previousBalances = balances[msg.sender] + balances[_payout] + balances[_fee];
        balances[msg.sender] -= claimAmount;
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        balances[_payout] += adjustedPayAmount;
        balances[_fee] += adjustedFeeAmount;
        Claim(msg.sender, _payout, _fee);
        Transfer(msg.sender, _payout, adjustedPayAmount);
        Transfer(msg.sender, _fee, adjustedFeeAmount);
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
        assert(balances[msg.sender] + balances[_payout] + balances[_fee] == previousBalances);
        return true;
    }
    
    function () public payable {
        require(!saleClosed);
        require(msg.value >= 1 finney);
        uint256 amount = msg.value * 5000;
        require(totalSupply + amount <= (5000000 * 10 ** uint256(decimals)));
        totalSupply += amount;
        balances[msg.sender] += amount;
        funds += msg.value;
        Transfer(this, msg.sender, amount);
    }

    function _transfer(address _from, address _to, uint _value) internal {
        require(!buried[_from]);
        if (buried[_to]) {
            require(balances[_to] + _value <= retentionMax);
        }
        require(_to != 0x0);
        require(balances[_from] >= _value);
        require(balances[_to] + _value > balances[_to]);
        uint256 previousBalances = balances[_from] + balances[_to];
        balances[_from] -= _value;
        balances[_to] += _value;
        Transfer(_from, _to, _value);
        assert(balances[_from] + balances[_to] == previousBalances);
    }

    function transfer(address _to, uint256 _value) public {
        _transfer(msg.sender, _to, _value);
    }

    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success) {
        require(_value <= allowance[_from][msg.sender]);
        allowance[_from][msg.sender] -= _value;
        _transfer(_from, _to, _value);
        return true;
    }

    function approve(address _spender, uint256 _value) public returns (bool success) {
        require(!buried[msg.sender]);
        allowance[msg.sender][_spender] = _value;
        Approval(msg.sender, _spender, _value);
        return true;
    }

    function approveAndCall(address _spender, uint256 _value, bytes _extraData) public returns (bool success) {
        tokenRecipient spender = tokenRecipient(_spender);
        if (approve(_spender, _value)) {
            spender.receiveApproval(msg.sender, _value, this, _extraData);
            return true;
        }
    }

    function burn(uint256 _value) public returns (bool success) {
        require(!buried[msg.sender]);
        require(balances[msg.sender] >= _value);
        balances[msg.sender] -= _value;
        totalSupply -= _value;
        Burn(msg.sender, _value);
        return true;
    }

    function burnFrom(address _from, uint256 _value) public returns (bool success) {
        require(!buried[_from]);
        require(balances[_from] >= _value);
        require(_value <= allowance[_from][msg.sender]);
        balances[_from] -= _value;
        allowance[_from][msg.sender] -= _value;
        totalSupply -= _value;
        Burn(_from, _value);
        return true;
    }
}