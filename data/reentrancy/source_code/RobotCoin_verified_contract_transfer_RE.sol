/*
 * ===== SmartInject Injection Details =====
 * Function      : transfer
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 2 findings
 * Total Found   : 3 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-benign (SWC-107)
 * 2. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the recipient contract before balance updates occur. The vulnerability requires multiple transactions to exploit:
 * 
 * **Changes Made:**
 * 1. Added a pre-transfer notification mechanism that calls `onTokenReceived()` on the recipient contract
 * 2. The external call occurs BEFORE `_transfer()` executes, creating a reentrancy window
 * 3. Balance checks and updates in `_transfer()` happen after the external call
 * 
 * **Multi-Transaction Exploitation:**
 * 1. **Transaction 1**: Attacker calls `transfer()` to their malicious contract
 * 2. **During Transaction 1**: The malicious contract's `onTokenReceived()` is called before balance updates
 * 3. **Reentrancy Window**: The malicious contract can call `transfer()` again while original balances are unchanged
 * 4. **Transaction 2+**: Multiple reentrant calls can occur, each seeing stale balance state
 * 5. **State Accumulation**: Each reentrant call processes based on the original balance, allowing overdrafts
 * 
 * **Why Multi-Transaction is Required:**
 * - The vulnerability exploits the timing between the external call and balance updates
 * - Multiple reentrant calls are needed to accumulate sufficient drainage
 * - Each reentrant call depends on the persistent state from previous calls
 * - The attack builds up over multiple function invocations within the same transaction context
 * - The stateful nature means the vulnerability's impact compounds across calls
 * 
 * **Realistic Integration:**
 * - The notification mechanism appears legitimate (common in modern token standards)
 * - The code maintains original functionality while introducing the flaw
 * - The vulnerability is subtle and could easily be missed in code reviews
 */
pragma solidity ^0.4.16;

contract Ownable {
    
    address public owner;
    
    function Ownable() public { 
        owner = msg.sender;
    }
 
    modifier onlyOwner() { 
        require(msg.sender == owner);
        _;
    }
 
    function transferOwnership(address _owner) public onlyOwner { 
        owner = _owner;
    }
    
}

contract RobotCoin is Ownable{
    
  modifier onlySaleAgent() { 
    require(msg.sender == saleAgent);
    _;
  }
    
  modifier onlyMasters() { 
    require(msg.sender == saleAgent || msg.sender == owner);
    _;
  }

  string public name; 
  string public symbol; 
  uint8 public decimals; 
     
  uint256 private tokenTotalSupply;
  address private tokenHolder;
  bool public usersCanTransfer;
  
  address public saleAgent; 
  
  mapping (address => uint256) private  balances;
  mapping (address => mapping (address => uint256)) private allowed; 
  
  event Transfer(address indexed _from, address indexed _to, uint256 _value);  
  event Approval(address indexed _owner, address indexed _spender, uint256 _value); 

  function RobotCoin () public {
    name = "RobotCoin"; 
    symbol = "RBC"; 
    decimals = 3; 
    
    tokenHolder = owner;
        
    tokenTotalSupply = 500000000000; 
    balances[this] = 250000000000;
    balances[tokenHolder] = 250000000000;
    
    usersCanTransfer = true;
  }

  function totalSupply() public constant returns (uint256 _totalSupply){ 
    return tokenTotalSupply;
    }
   
  function setTransferAbility(bool _usersCanTransfer) public onlyMasters{
    usersCanTransfer = _usersCanTransfer;
  }
  
  function setSaleAgent(address newSaleAgnet) public onlyMasters{ 
    saleAgent = newSaleAgnet;
  }
  
  function balanceOf(address _owner) public constant returns (uint balance) { 
    return balances[_owner];
  }

  function allowance(address _owner, address _spender) public constant returns (uint256 remaining){ 
    return allowed[_owner][_spender];
  }
  
  function approve(address _spender, uint256 _value) public returns (bool success){  
    allowed[msg.sender][_spender] += _value;
    emit Approval(msg.sender, _spender, _value);
    return true;
  }
  
  function _transfer(address _from, address _to, uint256 _value) internal returns (bool){ 
    require (_to != 0x0); 
    require(balances[_from] >= _value); 
    require(balances[_to] + _value >= balances[_to]); 

    balances[_from] -= _value; 
    balances[_to] += _value;

    emit Transfer(_from, _to, _value);
    return true;
  }

  function transfer(address _to, uint256 _value) public returns (bool success) { 
    require(usersCanTransfer || (msg.sender == owner));
    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
    
    // Notify recipient before state update - creates reentrancy window
    if(_isContract(_to)) {
        // Call external contract to notify of incoming transfer
        _to.call(abi.encodeWithSignature("onTokenReceived(address,uint256)", msg.sender, _value));
        // Continue execution regardless of call result
    }
    
    // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
    return _transfer(msg.sender, _to, _value);
  }

  function _isContract(address _addr) internal view returns (bool) {
    uint256 length;
    assembly { length := extcodesize(_addr) }
    return (length > 0);
  }

  function serviceTransfer(address _to, uint256 _value) public onlySaleAgent returns (bool success) { 
    return _transfer(this, _to, _value);
  }

  function transferFrom(address _from, address _to, uint256 _value) public returns (bool success) {   
    require(usersCanTransfer);
    require(_value <= allowed[_from][_to]);
    allowed[_from][_to] -= _value;  
    return _transfer(_from, _to, _value); 
  }
  
  function transferEther(uint256 etherAmmount) public onlyOwner{ 
    require(this.balance >= etherAmmount); 
    owner.transfer(etherAmmount); 
  }
}
