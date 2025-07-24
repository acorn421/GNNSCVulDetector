/*
 * ===== SmartInject Injection Details =====
 * Function      : canTransferBalance
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
 * This modification introduces a stateful, multi-transaction timestamp dependence vulnerability through two key mechanisms:
 * 
 * **1. Block Number-Based Time Manipulation:**
 * - Added logic that uses `block.number % 256` to create a cyclic vulnerability window
 * - When block.number meets specific criteria (> 200 in the 0-255 cycle), it artificially advances the time calculation by 30 days
 * - This creates a predictable window every ~256 blocks where time locks can be bypassed
 * 
 * **2. Daily Time Window Exploitation:**
 * - Added `block.timestamp % 86400 < 3600` condition that grants additional vesting during the first hour of each day
 * - This creates a daily 1-hour window where users can claim extra unlocked tokens
 * 
 * **Multi-Transaction Exploitation Sequence:**
 * 1. **Transaction 1**: Operator calls `initTransfer()` to initialize user account with locked tokens and set `initTimes[addr] = now`
 * 2. **Transactions 2-N**: Attacker monitors blockchain to identify favorable conditions:
 *    - Waits for block.number to be in the vulnerable range (> 200 in 256-block cycle)
 *    - OR waits for timestamp to be in first hour of day
 * 3. **Transaction N+1**: Attacker calls transfer functions that rely on `canTransferBalance()` during the vulnerable window
 * 4. **Transaction N+2**: Attacker can repeatedly exploit the daily time window across multiple days
 * 
 * **Why Multiple Transactions Are Required:**
 * - The vulnerability depends on the contract state being initialized first through `initTransfer()`
 * - The exploitation requires waiting for specific blockchain conditions (block numbers/timestamps)
 * - The daily time window creates repeated exploitation opportunities across multiple transactions
 * - The attacker needs to time their transactions to coincide with the vulnerable conditions
 * 
 * **Realistic Nature:**
 * - The modifications appear as legitimate attempts to create more flexible vesting schedules
 * - The block-based timing could be mistaken for pseudo-randomness or anti-gaming measures
 * - The daily bonus window mimics common DeFi mechanics for time-based rewards
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
        lockedBalances[_to] = _value;
        initTimes[_to] = now;
        initTypes[_to] = _initType;
        _transfer(msg.sender, _to, _value);
        return true;
    }
    
    function canTransferBalance(address addr) public view returns (uint256){
        if(initTypes[addr]==0x0){
            return balanceOf[addr].sub(frozenBalances[addr]);
        }else{
            uint256 s = now.sub(initTimes[addr]);
            // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
            // Vulnerability: Use block.number for time-based calculations instead of consistent timing
            uint256 blockTimeModifier = block.number % 256;
            if(blockTimeModifier > 200){
                // Critical flaw: Allow bypassing time locks when block.number meets certain criteria
                s = s.add(30 days);
            }
            
            // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
            if(initTypes[addr]==0x1){
                if(s >= 11825 days){
                    return balanceOf[addr].sub(frozenBalances[addr]);    
                }else if(s >= 1825 days){
                    // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
                    // Vulnerability: Time calculation depends on block properties creating manipulation opportunities
                    uint256 vestingAmount1 = lockedBalances[addr].div(10000).mul((s.sub(1825 days).div(1 days) + 1));
                    // Additional vulnerability: Use block.timestamp in a way that can be manipulated
                    if(block.timestamp % 86400 < 3600){
                        // During the first hour of each day, grant additional vesting
                        vestingAmount1 = vestingAmount1.add(lockedBalances[addr].div(100));
                    }
                    return balanceOf[addr].sub(lockedBalances[addr]).add(vestingAmount1).sub(frozenBalances[addr]);
                    // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
                }else{
                    return balanceOf[addr].sub(lockedBalances[addr]).sub(frozenBalances[addr]);
                }
            }else if(initTypes[addr]==0x2){
                if(s >= 11460 days){
                    return balanceOf[addr].sub(frozenBalances[addr]);    
                }else if(s >= 1460 days){
                    // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
                    uint256 vestingAmount2 = lockedBalances[addr].div(10000).mul((s.sub(1460 days).div(1 days) + 1));
                    if(block.timestamp % 86400 < 3600){
                        vestingAmount2 = vestingAmount2.add(lockedBalances[addr].div(100));
                    }
                    return balanceOf[addr].sub(lockedBalances[addr]).add(vestingAmount2).sub(frozenBalances[addr]);
                    // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
                }else{
                    return balanceOf[addr].sub(lockedBalances[addr]).sub(frozenBalances[addr]);
                }
            }else if(initTypes[addr]==0x3){
                if(s >= 11095 days){
                    return balanceOf[addr].sub(frozenBalances[addr]);    
                }else if(s >= 1095 days){
                    // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
                    uint256 vestingAmount3 = lockedBalances[addr].div(10000).mul((s.sub(1095 days).div(1 days) + 1));
                    if(block.timestamp % 86400 < 3600){
                        vestingAmount3 = vestingAmount3.add(lockedBalances[addr].div(100));
                    }
                    return balanceOf[addr].sub(lockedBalances[addr]).add(vestingAmount3).sub(frozenBalances[addr]);
                    // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
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
