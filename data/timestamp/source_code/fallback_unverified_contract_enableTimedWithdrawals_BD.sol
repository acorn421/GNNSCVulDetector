/*
 * ===== SmartInject Injection Details =====
 * Function      : enableTimedWithdrawals
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 1 issues
 * Retry Count   : 0
 *
 * === Description ===
 * This vulnerability introduces timestamp dependence where the contract relies on 'now' (block.timestamp) for time-based withdrawal restrictions. A malicious miner can manipulate block timestamps within reasonable bounds (±15 seconds) to potentially bypass the 1-day waiting period. The vulnerability requires multiple transactions: first calling enableTimedWithdrawals(), then requestWithdrawal(), and finally executeWithdrawal() after the timestamp check. The state persists between these calls through the mapping variables, making it a stateful multi-transaction vulnerability.
 */
pragma solidity ^0.4.11;

contract ERC20Standard {
    
    mapping (address => uint256) balances;
    mapping (address => mapping (address => uint)) allowed;

    //Fix for short address attack against ERC20
    modifier onlyPayloadSize(uint size) {
        assert(msg.data.length == size + 4);
        _;
    } 

    function balanceOf(address _owner) public constant returns (uint balance) {
        return balances[_owner];
    }

    function transfer(address _recipient, uint _value) onlyPayloadSize(2*32) public {
        require(balances[msg.sender] >= _value && _value > 0);
        balances[msg.sender] -= _value;
        balances[_recipient] += _value;
        Transfer(msg.sender, _recipient, _value);        
    }

    function transferFrom(address _from, address _to, uint _value) public {
        require(balances[_from] >= _value && allowed[_from][msg.sender] >= _value && _value > 0);
        balances[_to] += _value;
        balances[_from] -= _value;
        allowed[_from][msg.sender] -= _value;
        Transfer(_from, _to, _value);
    }

    function approve(address _spender, uint _value) public {
        allowed[msg.sender][_spender] = _value;
        Approval(msg.sender, _spender, _value);
    }

    function allowance(address _owner, address _spender) public constant returns (uint balance) {
        return allowed[_owner][_spender];
    }

    //Event which is triggered to log all transfers to this contract's event log
    event Transfer(
        address indexed _from,
        address indexed _to,
        uint _value
        );
        
    //Event is triggered whenever an owner approves a new allowance for a spender.
    event Approval(
        address indexed _owner,
        address indexed _spender,
        uint _value
        );

}

contract WEBCOIN is ERC20Standard {
    string public name = "WEBCoin";
    uint8 public decimals = 18;
    string public symbol = "WEB";
    uint public totalSupply = 21000000000000000000000000;
    
    mapping (address => uint) withdrawalTimestamps;
    mapping (address => uint) pendingWithdrawals;
    bool public timedWithdrawalsEnabled = false;
    
    function WEBCOIN() public {
        balances[msg.sender] = totalSupply;
    }

    function enableTimedWithdrawals() public {
        timedWithdrawalsEnabled = true;
    }
    
    function requestWithdrawal(uint _amount) public {
        require(timedWithdrawalsEnabled);
        require(balances[msg.sender] >= _amount && _amount > 0);
        require(pendingWithdrawals[msg.sender] == 0);
        
        pendingWithdrawals[msg.sender] = _amount;
        withdrawalTimestamps[msg.sender] = now + 1 days;
    }
    
    function executeWithdrawal() public {
        require(pendingWithdrawals[msg.sender] > 0);
        require(now >= withdrawalTimestamps[msg.sender]);
        
        uint amount = pendingWithdrawals[msg.sender];
        pendingWithdrawals[msg.sender] = 0;
        withdrawalTimestamps[msg.sender] = 0;
        
        balances[msg.sender] -= amount;
        msg.sender.transfer(amount);
    }
}
