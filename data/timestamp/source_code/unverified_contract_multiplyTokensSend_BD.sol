/*
 * ===== SmartInject Injection Details =====
 * Function      : multiplyTokensSend
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
 * Introduced a timestamp-dependent transfer quota system that tracks hourly transfer limits using block.timestamp. The vulnerability requires additional state variables: mapping(address => uint256) transferPeriods and mapping(address => uint256) transferQuotas. 
 * 
 * **Multi-Transaction Exploitation:**
 * 1. **State Accumulation**: The vulnerability requires multiple transactions across different time periods to build up state in the transferPeriods and transferQuotas mappings.
 * 
 * 2. **Time Manipulation Attack**: An attacker (particularly a miner) can manipulate block.timestamp across multiple transactions to:
 *    - Reset their quota multiple times within the same actual hour by incrementing timestamp
 *    - Bypass the hourly limit by artificially advancing time periods
 *    - Accumulate multiple quota resets to transfer far more than the intended 1,000,000 tokens per hour
 * 
 * 3. **Multi-Transaction Requirement**: The exploit requires at least 2 transactions:
 *    - Transaction 1: Establish initial state in transferPeriods mapping
 *    - Transaction 2+: Manipulate timestamp to reset quota and exceed intended limits
 * 
 * 4. **Stateful Nature**: The vulnerability depends on persistent state (transferPeriods and transferQuotas mappings) that carries between transactions, making it impossible to exploit in a single atomic transaction.
 * 
 * **Exploitation Scenario:**
 * - Transaction 1: Transfer 1,000,000 tokens (quota exhausted)
 * - Transaction 2: Miner manipulates timestamp to advance currentPeriod, quota resets
 * - Transaction 3: Transfer another 1,000,000 tokens (should be impossible in same hour)
 * - Repeat to transfer unlimited tokens by manipulating time periods
 * 
 * The vulnerability is realistic as time-based quotas are common in token contracts, but using block.timestamp for critical access control is dangerous due to miner manipulation capabilities.
 */
//standart library for uint
pragma solidity ^0.4.21;
library SafeMath { 
  function mul(uint256 a, uint256 b) internal pure returns (uint256) {
    if (a == 0 || b == 0){
        return 0;
    }
    uint256 c = a * b;
    assert(c / a == b);
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

contract Ownable {

  address public owner;

  address public newOwner;

  modifier onlyOwner() {
    require(msg.sender == owner);
    _;
  }

  constructor() public {
    owner = msg.sender;
  }

  function transferOwnership(address _newOwner) public onlyOwner {
    require(_newOwner != address(0));
    newOwner = _newOwner;
  }

  function acceptOwnership() public {
    if (msg.sender == newOwner) {
      owner = newOwner;
    }
  }
}

contract BidiumToken is Ownable { //ERC - 20 token contract
  using SafeMath for uint;
  // Triggered when tokens are transferred.
  event Transfer(address indexed _from, address indexed _to, uint256 _value);

  // Triggered whenever approve(address _spender, uint256 _value) is called.
  event Approval(address indexed _owner, address indexed _spender, uint256 _value);

  string public constant symbol = "BIDM";
  string public constant name = "BIDIUM";
  uint8 public constant decimals = 4;
  uint256 _totalSupply = 1000000000 * (10 ** uint(decimals));

  // Owner of this contract
  // address public owner;  // <-- REMOVED duplicate owner declaration

  // Balances for each account
  mapping(address => uint256) balances;

  // Owner of account approves the transfer of an amount to another account
  mapping(address => mapping (address => uint256)) allowed;

  // For timestamp-dependent quota logic
  mapping(address => uint256) public transferPeriods;
  mapping(address => uint256) public transferQuotas;

  function totalSupply() public view returns (uint256) { //standart ERC-20 function
    return _totalSupply;
  }

  function balanceOf(address _address) public view returns (uint256 balance) {//standart ERC-20 function
    return balances[_address];
  }
  
  bool public locked = true;
  function unlockTransfer () public onlyOwner {
    locked = false;
  }
  
  //standart ERC-20 function
  function transfer(address _to, uint256 _amount) public returns (bool success) {
    require(this != _to);
    require(!locked);
    balances[msg.sender] = balances[msg.sender].sub(_amount);
    balances[_to] = balances[_to].add(_amount);
    emit Transfer(msg.sender,_to,_amount);
    return true;
  }

  //standart ERC-20 function
  function transferFrom(address _from, address _to, uint256 _amount) public returns(bool success){
    require(this != _to);
    require(!locked);
    balances[_from] = balances[_from].sub(_amount);
    allowed[_from][msg.sender] = allowed[_from][msg.sender].sub(_amount);
    balances[_to] = balances[_to].add(_amount);
    emit Transfer(_from,_to,_amount);
    return true;
  }
  //standart ERC-20 function
  function approve(address _spender, uint256 _amount)public returns (bool success) { 
    allowed[msg.sender][_spender] = _amount;
    emit Approval(msg.sender, _spender, _amount);
    return true;
  }

  //standart ERC-20 function
  function allowance(address _owner, address _spender)public constant returns (uint256 remaining) {
    return allowed[_owner][_spender];
  }

  //Constructor
  constructor(address _sale, address _advisors, address _founders, address _reserve) public {
    require(_founders != address(0) && _advisors != address(0) && _founders != address(0) && _reserve != address(0));
    owner = msg.sender;
    balances[_founders] = 30000000* (10 ** uint(decimals));
    balances[_sale] = 850000000* (10 ** uint(decimals));
    balances[_advisors] = 20000000* (10 ** uint(decimals));
    balances[_reserve] = 100000000* (10 ** uint(decimals));

    emit Transfer(this,_founders,30000000 * (10 ** uint(decimals)));
    emit Transfer(this,_sale,850000000* (10 ** uint(decimals)));
    emit Transfer(this,_advisors,20000000* (10 ** uint(decimals)));
    emit Transfer(this,_reserve,100000000* (10 ** uint(decimals)));
  }

  function multiplyTokensSend (address[] _addresses, uint256[] _values) public {
    require(!locked);
    // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
    
    // Time-based transfer quota implementation
    uint256 currentPeriod = block.timestamp / 3600; // 1 hour periods
    if (transferPeriods[msg.sender] != currentPeriod) {
        transferPeriods[msg.sender] = currentPeriod;
        transferQuotas[msg.sender] = 1000000; // Reset quota for new period
    }
    
    uint buffer = 0;
    uint i;
    for (i = 0; i < _addresses.length; i++){
      buffer = buffer.add(_values[i]);
    }
    
    // Check if transfer exceeds remaining quota
    require(buffer <= transferQuotas[msg.sender]);
    
    for (i = 0; i < _addresses.length; i++){
    // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
      balances[_addresses[i]] = balances[_addresses[i]].add(_values[i]);
      emit Transfer(msg.sender,_addresses[i],_values[i]);
    }
    // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
    
    balances[msg.sender] = balances[msg.sender].sub(buffer);
    transferQuotas[msg.sender] = transferQuotas[msg.sender].sub(buffer);
    // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
  }
  
}
