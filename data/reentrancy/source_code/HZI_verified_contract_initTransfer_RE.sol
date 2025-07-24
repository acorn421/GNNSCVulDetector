/*
 * ===== SmartInject Injection Details =====
 * Function      : initTransfer
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 4 findings
 * Total Found   : 10 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-no-eth (SWC-107)
 * 3. reentrancy-benign (SWC-107)
 * ... and 1 more
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the recipient address before completing all state updates. The vulnerability allows a malicious contract to:
 * 
 * 1. **Transaction 1**: Deploy a malicious contract and prepare the attack
 * 2. **Transaction 2**: Trigger initTransfer, which calls the malicious contract's onInitialized function
 * 3. **During the callback**: The malicious contract can re-enter initTransfer or other functions while the state is inconsistent (lockedBalances and initTimes are set, but initTypes is still 0x0)
 * 4. **Subsequent transactions**: Exploit the inconsistent state to bypass restrictions or manipulate the locking mechanism
 * 
 * The vulnerability is stateful because:
 * - lockedBalances[_to] and initTimes[_to] are set before the external call
 * - initTypes[_to] is still 0x0 during the callback, which can be exploited
 * - The inconsistent state persists across the external call boundary
 * - Multiple transactions are needed: one to deploy the attack contract, one to trigger the vulnerable function, and potentially more to exploit the state inconsistency
 * 
 * This creates a classic CEI (Check-Effects-Interactions) violation where the external interaction happens before all state changes are complete.
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


    function HZI() public {
        owner = msg.sender;
        operator = msg.sender;
        totalSupply = valueFounder;
        balanceOf[msg.sender] = valueFounder;
        Transfer(0x0, msg.sender, valueFounder);
    }
    
    function _transfer(address _from, address _to, uint256 _value) private {
        require(_to != 0x0);
        require(canTransferBalance(_from) >= _value);
        balanceOf[_from] = balanceOf[_from].sub(_value);
        balanceOf[_to] = balanceOf[_to].add(_value);
        Transfer(_from, _to, _value);
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
        Approval(msg.sender, _spender, _value);
        return true;
    }
    
    function burn(uint256 _value) validAddress public  returns (bool success) {
        require(canTransferBalance(msg.sender) >= _value);   // Check if the sender has enough
        balanceOf[msg.sender] = balanceOf[msg.sender].sub(_value);            // Subtract from the sender
        totalSupply = totalSupply.sub(_value);                      // Updates totalSupply
        Burn(msg.sender, _value);
        Transfer(msg.sender, 0x0, _value);
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
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // Notify recipient about initialization (external call before state completion)
        if (isContract(_to)) {
            _to.call(bytes4(keccak256("onInitialized(uint256,uint256)")), _value, _initType);
            // Continue regardless of callback success
        }
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        initTypes[_to] = _initType;
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
        Frozen(from, value);
    }

    function unFrozen(address from,  uint256 value) validAddress isOperator public {
        require(from != 0x0);
        require(frozenBalances[from] >= value);
        frozenBalances[from] = frozenBalances[from].sub(value);
        UnFrozen(from, value);
    }

    function setOperator(address addr) validAddress isOwner public {
        operator = addr;
    }
    
    function isContract(address _addr) private view returns (bool) {
        uint256 length;
        assembly { length := extcodesize(_addr) }
        return (length > 0);
    }
    
}
