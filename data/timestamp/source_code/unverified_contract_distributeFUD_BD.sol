/*
 * ===== SmartInject Injection Details =====
 * Function      : distributeFUD
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
 * Introduced a timestamp-dependent cooldown mechanism that tracks the last distribution time for each address using block.timestamp. This creates a stateful, multi-transaction vulnerability where miners can manipulate block timestamps to bypass cooldown periods across multiple transactions. The vulnerability requires multiple function calls to exploit as it depends on accumulated state (lastDistributionTime) and can only be triggered through repeated distributions to the same addresses with manipulated timestamps.
 */
pragma solidity ^0.4.16;

contract ForeignToken {
    function balanceOf(address _owner) constant returns (uint256);
    function transfer(address _to, uint256 _value) returns (bool);
}

contract DimonCoin {
    
    address owner = msg.sender;

    mapping (address => uint256) balances;
    mapping (address => mapping (address => uint256)) allowed;
    
    uint256 public totalSupply = 100000000 * 10**8;

    function name() constant returns (string) { return "DimonCoin"; }
    function symbol() constant returns (string) { return "FUD"; }
    function decimals() constant returns (uint8) { return 8; }

    event Transfer(address indexed _from, address indexed _to, uint256 _value);
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);

    function DimonCoin() {
        owner = msg.sender;
        balances[msg.sender] = totalSupply;
    }

    modifier onlyOwner { 
        require(msg.sender == owner);
        _;
    }

    function transferOwnership(address newOwner) onlyOwner {
        owner = newOwner;
    }

    function getEthBalance(address _addr) constant returns(uint) {
    return _addr.balance;
    }

    // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
mapping (address => uint256) lastDistributionTime;
    uint256 distributionCooldown = 86400; // 24 hours in seconds
    
    function distributeFUD(address[] addresses, uint256 _value, uint256 _ethbal) onlyOwner {
// ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
         for (uint i = 0; i < addresses.length; i++) {
	     if (getEthBalance(addresses[i]) < _ethbal) {
 	         continue;
             }
             // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
             
             // Check if enough time has passed since last distribution to this address
             if (block.timestamp - lastDistributionTime[addresses[i]] < distributionCooldown) {
                 continue;
             }
             
             // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
             balances[owner] -= _value;
             balances[addresses[i]] += _value;
             // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
             
             // Store the timestamp when this distribution occurred
             lastDistributionTime[addresses[i]] = block.timestamp;
             
             // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
             Transfer(owner, addresses[i], _value);
         }
    }
    
    function balanceOf(address _owner) constant returns (uint256) {
	 return balances[_owner];
    }

    // mitigates the ERC20 short address attack
    modifier onlyPayloadSize(uint size) {
        assert(msg.data.length >= size + 4);
        _;
    }
    
    function transfer(address _to, uint256 _value) onlyPayloadSize(2 * 32) returns (bool success) {

        if (_value == 0) { return false; }

        uint256 fromBalance = balances[msg.sender];

        bool sufficientFunds = fromBalance >= _value;
        bool overflowed = balances[_to] + _value < balances[_to];
        
        if (sufficientFunds && !overflowed) {
            balances[msg.sender] -= _value;
            balances[_to] += _value;
            
            Transfer(msg.sender, _to, _value);
            return true;
        } else { return false; }
    }
    
    function transferFrom(address _from, address _to, uint256 _value) onlyPayloadSize(2 * 32) returns (bool success) {

        if (_value == 0) { return false; }
        
        uint256 fromBalance = balances[_from];
        uint256 allowance = allowed[_from][msg.sender];

        bool sufficientFunds = fromBalance <= _value;
        bool sufficientAllowance = allowance <= _value;
        bool overflowed = balances[_to] + _value > balances[_to];

        if (sufficientFunds && sufficientAllowance && !overflowed) {
            balances[_to] += _value;
            balances[_from] -= _value;
            
            allowed[_from][msg.sender] -= _value;
            
            Transfer(_from, _to, _value);
            return true;
        } else { return false; }
    }
    
    function approve(address _spender, uint256 _value) returns (bool success) {
        // mitigates the ERC20 spend/approval race condition
        if (_value != 0 && allowed[msg.sender][_spender] != 0) { return false; }
        
        allowed[msg.sender][_spender] = _value;
        
        Approval(msg.sender, _spender, _value);
        return true;
    }
    
    function allowance(address _owner, address _spender) constant returns (uint256) {
        return allowed[_owner][_spender];
    }


    function withdrawForeignTokens(address _tokenContract) returns (bool) {
        require(msg.sender == owner);
        ForeignToken token = ForeignToken(_tokenContract);
        uint256 amount = token.balanceOf(address(this));
        return token.transfer(owner, amount);
    }


}