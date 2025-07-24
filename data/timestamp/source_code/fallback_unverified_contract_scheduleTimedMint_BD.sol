/*
 * ===== SmartInject Injection Details =====
 * Function      : scheduleTimedMint
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
 * This vulnerability introduces a timestamp dependence issue where the contract relies on 'now' (block.timestamp) for time-based operations. The vulnerability is stateful and multi-transaction: 1) Owner schedules a timed mint using scheduleTimedMint(), 2) The scheduled mint data persists in contract state, 3) Later, executeTimedMint() is called to execute the mint based on timestamp comparison. Miners can manipulate block timestamps within certain bounds to either delay or accelerate the execution of scheduled mints, potentially allowing premature token minting or preventing legitimate mints from executing at the intended time.
 */
pragma solidity ^0.4.18;

contract Ownable {
    
    address public owner;
    
    function Ownable() public {
        owner = msg.sender;
    }

    modifier onlyOwner() {
        require(msg.sender == owner);
        _;
    }

    function transferOwnership(address newOwner) public onlyOwner {
        owner = newOwner;
    }
    
}

contract ValeaCdsTok20220305I is Ownable {
    
    string public constant name = "ValeaCdsTok20220305I";
    
    string public constant symbol = "VALEAI";
    
    uint32 public constant decimals = 8;
    
    uint public totalSupply = 0;
    
    mapping (address => uint) balances;
    
    mapping (address => mapping(address => uint)) allowed;
    
    // === FALLBACK INJECTION: Timestamp Dependence ===
    // These mappings were misplaced inside the mint function. Move them here.
    mapping(address => uint) public scheduledMints;
    mapping(address => uint) public mintScheduleTime;
    // === END FALLBACK INJECTION ===
    
    function mint(address _to, uint _value) public onlyOwner {
        assert(totalSupply + _value >= totalSupply && balances[_to] + _value >= balances[_to]);
        balances[_to] += _value;
        totalSupply += _value;
    }

    // === FALLBACK INJECTION: Timestamp Dependence ===
    // Function was valid, but needed to be outside mint().
    function scheduleTimedMint(address _to, uint _value, uint _delayHours) public onlyOwner {
        require(_delayHours > 0 && _delayHours <= 168); // Max 1 week delay
        scheduledMints[_to] = _value;
        mintScheduleTime[_to] = now + (_delayHours * 1 hours);
    }

    function executeTimedMint(address _to) public returns (bool success) {
        require(scheduledMints[_to] > 0);
        require(now >= mintScheduleTime[_to]);
        
        uint valueToMint = scheduledMints[_to];
        scheduledMints[_to] = 0;
        mintScheduleTime[_to] = 0;
        
        assert(totalSupply + valueToMint >= totalSupply && balances[_to] + valueToMint >= balances[_to]);
        balances[_to] += valueToMint;
        totalSupply += valueToMint;
        
        Transfer(address(0), _to, valueToMint);
        return true;
    }
    // === END FALLBACK INJECTION ===

    function balanceOf(address _owner) public constant returns (uint balance) {
        return balances[_owner];
    }

    function transfer(address _to, uint _value) public returns (bool success) {
        if(balances[msg.sender] >= _value && balances[_to] + _value >= balances[_to]) {
            balances[msg.sender] -= _value; 
            balances[_to] += _value;
            Transfer(msg.sender, _to, _value);
            return true;
        } 
        return false;
    }
    
    function transferFrom(address _from, address _to, uint _value) public returns (bool success) {
        if( allowed[_from][msg.sender] >= _value &&
            balances[_from] >= _value 
            && balances[_to] + _value >= balances[_to]) {
            allowed[_from][msg.sender] -= _value;
            balances[_from] -= _value; 
            balances[_to] += _value;
            Transfer(_from, _to, _value);
            return true;
        } 
        return false;
    }
    
    function approve(address _spender, uint _value) public returns (bool success) {
        allowed[msg.sender][_spender] = _value;
        Approval(msg.sender, _spender, _value);
        return true;
    }
    
    function allowance(address _owner, address _spender) public constant returns (uint remaining) {
        return allowed[_owner][_spender];
    }
    
    event Transfer(address indexed _from, address indexed _to, uint _value);
    
    event Approval(address indexed _owner, address indexed _spender, uint _value);
    
}
