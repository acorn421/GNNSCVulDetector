/*
 * ===== SmartInject Injection Details =====
 * Function      : initTransfer
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 6 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Introduced a timestamp-dependent bonus system that rewards users based on the time of day when initTransfer is called. The vulnerability allows miners to manipulate block timestamps to consistently trigger the bonus conditions, creating an unfair advantage. The bonus affects the locked balance calculation, which impacts future unlock schedules through the canTransferBalance function. This creates a stateful, multi-transaction vulnerability where:
 * 
 * 1. Transaction 1: Miner calls initTransfer with manipulated timestamp to trigger bonus
 * 2. Transaction 2+: The inflated lockedBalances persist and affect all future unlock calculations
 * 3. Future transactions: Users can unlock more tokens than intended due to the manipulated bonus
 * 
 * The vulnerability requires multiple transactions because the bonus is stored in state (lockedBalances) during initTransfer, and the benefit is realized later when canTransferBalance is called in subsequent transfer operations. The 24-hour modulo check creates predictable windows that miners can exploit by manipulating block timestamps within reasonable bounds (15-second tolerance in Ethereum).
 */
pragma solidity ^0.4.11;


library SafeMath {
    
  function mul(uint256 a, uint256 b) internal pure returns (uint256) {
    if (a == 0) {
      return 0;
    }
    uint256 c = a * b;
    assert(c / a == b);
    return c;
  }

  function div(uint256 a, uint256 b) internal pure returns (uint256) {
    uint256 c = a / b;
    return c;
  }

  function sub(uint256 a, uint256 b) internal pure returns (uint256) {
    assert(b <= a);
    return a - b;
  }

  function add(uint256 a, uint256 b) internal pure returns (uint256) {
    uint256 c = a + b;
    assert(c >= a);
    return c;
  }
}

contract HZI {
    
    using SafeMath for uint256;
    
    string public name = "HZI";      //  token name
    
    string public symbol = "HZI";           //  token symbol
    
    uint256 public decimals = 8;            //  token digit

    mapping (address => uint256) public balanceOf;
    
    mapping (address => mapping (address => uint256)) public allowance;
    
    mapping (address => uint256) public frozenBalances;
    mapping (address => uint256) public lockedBalances;
    
    mapping (address => uint256) public initTimes;
    
    mapping (address => uint) public initTypes;
    
    uint256 public totalSupply = 0;

    uint256 constant valueFounder = 1000000000000000000;
    
    address owner = 0x0;
    
    address operator = 0x0;
    bool inited = false;

    modifier isOwner {
        assert(owner == msg.sender);
        _;
    }
    
    modifier isOperator {
        assert(operator == msg.sender);
        _;
    }

    modifier validAddress {
        assert(0x0 != msg.sender);
        _;
    }
    
    event Transfer(address indexed _from, address indexed _to, uint256 _value);
    
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);
    
    event Burn(address indexed from, uint256 value);
    event Frozen(address indexed from, uint256 value);
    event UnFrozen(address indexed from, uint256 value);


    constructor() public {
        owner = msg.sender;
        operator = msg.sender;
        totalSupply = valueFounder;
        balanceOf[msg.sender] = valueFounder;
        emit Transfer(0x0, msg.sender, valueFounder);
    }
    
    function _transfer(address _from, address _to, uint256 _value) private {
        require(_to != 0x0);
        require(canTransferBalance(_from) >= _value);
        balanceOf[_from] = balanceOf[_from].sub(_value);
        balanceOf[_to] = balanceOf[_to].add(_value);
        emit Transfer(_from, _to, _value);
    }
    
    function transfer(address _to, uint256 _value) validAddress public returns (bool success) {
        _transfer(msg.sender, _to, _value);
        return true;
    }

    function transferFrom(address _from, address _to, uint256 _value) validAddress public returns (bool success) {
        require(_value <= allowance[_from][msg.sender]);
        allowance[_from][msg.sender] = allowance[_from][msg.sender].sub(_value);
        _transfer(_from, _to, _value);
        return true;
    }

    function approve(address _spender, uint256 _value) validAddress public returns (bool success) {
        require(canTransferBalance(msg.sender) >= _value);
        allowance[msg.sender][_spender] = _value;
        emit Approval(msg.sender, _spender, _value);
        return true;
    }
    
    function burn(uint256 _value) validAddress public  returns (bool success) {
        require(canTransferBalance(msg.sender) >= _value);   // Check if the sender has enough
        balanceOf[msg.sender] = balanceOf[msg.sender].sub(_value);            // Subtract from the sender
        totalSupply = totalSupply.sub(_value);                      // Updates totalSupply
        emit Burn(msg.sender, _value);
        emit Transfer(msg.sender, 0x0, _value);
        return true;
    }

    function initTransferArr(address[] _arr_addr, uint256[] _arr_value,uint[] _arr_initType) validAddress isOperator public returns (bool success) {
        require(_arr_addr.length == _arr_value.length && _arr_value.length == _arr_initType.length);
        require(_arr_addr.length > 0 && _arr_addr.length < 100);
        require(!inited);
        for (uint i = 0; i < _arr_addr.length ; ++i) {
            initTransfer(_arr_addr[i],_arr_value[i],_arr_initType[i]);
        }
        inited = true;
        return true;
    }

    function initTransfer(address _to, uint256 _value, uint _initType) validAddress isOperator public returns (bool success) {
        require(_initType == 0x1 || _initType == 0x2 || _initType == 0x3);
        require(initTypes[_to]==0x0);
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        
        // Timestamp-dependent bonus calculation for early adopters
        uint256 currentTime = now;
        uint256 bonusMultiplier = 1000; // Base multiplier (1.0x)
        
        // Check if this is within the "early adopter" time window
        if (currentTime % 86400 < 3600) { // First hour of each day
            bonusMultiplier = 1200; // 1.2x bonus for early adopters
        } else if (currentTime % 86400 < 7200) { // Second hour of each day
            bonusMultiplier = 1100; // 1.1x bonus
        }
        
        // Apply bonus to locked balance - creates timestamp manipulation incentive
        uint256 adjustedValue = _value.mul(bonusMultiplier).div(1000);
        lockedBalances[_to] = adjustedValue;
        
        // Store both original and adjusted timestamps for bonus tracking
        initTimes[_to] = currentTime;
        initTypes[_to] = _initType;
        
        // Transfer the original value but lock the adjusted (potentially higher) amount
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
        _transfer(msg.sender, _to, _value);
        return true;
    }
    
    function canTransferBalance(address addr) public view returns (uint256){
        if(initTypes[addr]==0x0){
            return balanceOf[addr].sub(frozenBalances[addr]);
        }else{
            uint256 s = now.sub(initTimes[addr]);
            if(initTypes[addr]==0x1){
                if(s >= 11825 days){
                    return balanceOf[addr].sub(frozenBalances[addr]);    
                }else if(s >= 1825 days){
                    return balanceOf[addr].sub(lockedBalances[addr]).add(lockedBalances[addr].div(10000).mul((s.sub(1825 days).div(1 days) + 1))).sub(frozenBalances[addr]);
                }else{
                    return balanceOf[addr].sub(lockedBalances[addr]).sub(frozenBalances[addr]);
                }
            }else if(initTypes[addr]==0x2){
                if(s >= 11460 days){
                    return balanceOf[addr].sub(frozenBalances[addr]);    
                }else if(s >= 1460 days){
                    return balanceOf[addr].sub(lockedBalances[addr]).add(lockedBalances[addr].div(10000).mul((s.sub(1460 days).div(1 days) + 1))).sub(frozenBalances[addr]);
                }else{
                    return balanceOf[addr].sub(lockedBalances[addr]).sub(frozenBalances[addr]);
                }
            }else if(initTypes[addr]==0x3){
                if(s >= 11095 days){
                    return balanceOf[addr].sub(frozenBalances[addr]);    
                }else if(s >= 1095 days){
                    return balanceOf[addr].sub(lockedBalances[addr]).add(lockedBalances[addr].div(10000).mul((s.sub(1095 days).div(1 days) + 1))).sub(frozenBalances[addr]);
                }else{
                    return balanceOf[addr].sub(lockedBalances[addr]).sub(frozenBalances[addr]);
                }
            }else{
                return 0;
            }
      
        }
    }

    function frozen(address from,  uint256 value) validAddress isOperator public {
        require(from != 0x0);
        require(canTransferBalance(from) >= value);
        frozenBalances[from] = frozenBalances[from].add(value);
        emit Frozen(from, value);
    }

    function unFrozen(address from,  uint256 value) validAddress isOperator public {
        require(from != 0x0);
        require(frozenBalances[from] >= value);
        frozenBalances[from] = frozenBalances[from].sub(value);
        emit UnFrozen(from, value);
    }

    function setOperator(address addr) validAddress isOwner public {
        operator = addr;
    }
    
}