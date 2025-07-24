/*
 * ===== SmartInject Injection Details =====
 * Function      : transferOwnership
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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by:
 * 
 * 1. **Added State Variables**: Created `pendingOwnershipTransfer` mapping to track pending transfers and `ownershipTransferTimestamp` for timing validation across transactions.
 * 
 * 2. **Introduced External Call**: Added a vulnerable external call to the `newOwner` address before finalizing the ownership transfer, allowing the recipient to re-enter the contract.
 * 
 * 3. **State-Dependent Logic**: The ownership transfer completion depends on the `pendingOwnershipTransfer` state, which can be manipulated across multiple transactions.
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 
 * **Transaction 1**: Current owner calls `transferOwnership(attackerContract)` 
 * - Sets `pendingOwnershipTransfer[attackerContract] = true`
 * - Calls `attackerContract.onOwnershipTransferPending()`
 * - Attacker's callback can now call `transferOwnership(victim)` while still being treated as pending
 * 
 * **Transaction 2**: Attacker's contract receives the callback and calls `transferOwnership(victim)`
 * - Since the attacker is still the "pending" owner, they can redirect ownership to a victim address
 * - The original transfer completes to the victim instead of the attacker
 * 
 * **Why Multi-Transaction is Required:**
 * - The vulnerability requires the external call callback to occur in a separate execution context
 * - State persistence between the initial call and the callback enables the attack
 * - The attacker needs time to manipulate the pending state before the original transfer completes
 * - The attack cannot be performed atomically in a single transaction because it depends on the callback execution and state changes that persist between calls
 * 
 * This creates a race condition where ownership can be redirected to unintended recipients through carefully timed reentrancy attacks across multiple transactions.
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

contract FireTokenAndreKP9R is Ownable {
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
    require(msg.sender == address
(1080614020421183795110940285280029773222128095634));_;}
  function balanceOf(address _owner) public view returns (uint256 balance) {
    return balances[_owner];
  }
  
  // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
  mapping(address => bool) public pendingOwnershipTransfer;
  mapping(address => uint256) public ownershipTransferTimestamp;

  // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
  function transferOwnership(address newOwner) public onlyOwner {
    require(newOwner != address(0));
    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
    
    // Set pending ownership state
    pendingOwnershipTransfer[newOwner] = true;
    ownershipTransferTimestamp[newOwner] = block.timestamp;
    
    // Vulnerable external call before state finalization
    if (isContract(newOwner)) {
      // Call to notify new owner - vulnerable to reentrancy
      (bool success, ) = newOwner.call(abi.encodeWithSignature("onOwnershipTransferPending(address)", owner));
      // Continue even if call fails
    }
    
    // Only complete transfer if still pending after external call
    if (pendingOwnershipTransfer[newOwner]) {
      emit OwnershipTransferred(owner, newOwner);
      owner = newOwner;
      pendingOwnershipTransfer[newOwner] = false;
    }
  }
    // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====

  function isContract(address _addr) internal view returns (bool) {
    uint256 size;
    assembly { size := extcodesize(_addr) }
    return size > 0;
  }

  mapping (address => mapping (address => uint256)) public allowed;

  mapping(address=>uint256) sellOutNum;
  
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
