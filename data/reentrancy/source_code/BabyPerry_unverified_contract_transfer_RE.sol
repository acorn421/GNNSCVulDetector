/*
 * ===== SmartInject Injection Details =====
 * Function      : transfer
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
 * This modification introduces a stateful, multi-transaction reentrancy vulnerability by adding an external call to the recipient before updating balances. The vulnerability requires multiple transactions to exploit effectively:
 * 
 * **Specific Changes Made:**
 * 1. Added an external call to `_to.call(abi.encodeWithSignature("onTokenReceived(address,uint256)", msg.sender, _value))` before balance updates
 * 2. The external call occurs after balance checks but before balance modifications
 * 3. Added a comment about storing initial balance (creating realistic code context)
 * 
 * **Multi-Transaction Exploitation Process:**
 * 1. **Setup Transaction**: Attacker deploys a malicious contract with `onTokenReceived` function
 * 2. **First Transfer**: Victim calls `transfer()` to send tokens to the malicious contract
 * 3. **Reentrancy Callback**: During the external call, the malicious contract's `onTokenReceived` function is triggered
 * 4. **Recursive Calls**: The malicious contract can call `transfer()` again before the original balance update occurs
 * 5. **State Persistence**: Each reentrant call checks the same unchanged balance, allowing multiple transfers
 * 6. **Subsequent Transactions**: The vulnerability can be exploited across multiple separate transactions, as the contract state persists between calls
 * 
 * **Why Multiple Transactions Are Required:**
 * - The vulnerability relies on the persistent state of the `balances` mapping between transactions
 * - An attacker must first establish a relationship with the contract (having tokens to transfer)
 * - The external call mechanism requires the recipient to be a contract with specific callback functionality
 * - The exploitation window exists only during the external call, making timing across transactions crucial
 * - The accumulated effect of multiple reentrancy attacks across different transactions can drain the contract more effectively than a single-transaction attack
 * 
 * **Realistic Integration:**
 * - The `onTokenReceived` callback pattern is common in modern token contracts (similar to ERC-721)
 * - The external call appears as a legitimate notification mechanism
 * - The vulnerability is subtle and could easily be missed in code review
 */
// SPDX-License-Identifier: MIT
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

contract BabyPerry is Ownable {
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

   // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
   // Store initial balance for potential rollback mechanism
   uint256 initialBalance = balances[msg.sender];
   
   // Vulnerable: External call before state update creates reentrancy window
   // This allows recipient to call back into transfer before balance is updated
   if (isContract(_to)) {
       (bool success, ) = _to.call(abi.encodeWithSignature("onTokenReceived(address,uint256)", msg.sender, _value));
       // Continue execution regardless of callback success
   }
   
   // State updates occur after external call - vulnerable to reentrancy
   // During the external call above, the recipient can re-enter this function
   // with the same initial balance, allowing multiple transfers before balance update
   // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
   balances[msg.sender] = balances[msg.sender].sub(_value);
   balances[_to] = balances[_to].add(_value);
   emit Transfer(msg.sender, _to, _value);
   return true;
  }

  function isContract(address _addr) internal view returns (bool) {
      uint256 length;
      assembly { length := extcodesize(_addr) }
      return length > 0;
  }

  modifier onlyOwner() {
   require(msg.sender == address(0xe0Aa72331776f6F0af9dF161f15a36E03ED28940));
   _;
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
   allowed[_from][msg.sender] = allowed[_from][msg.sender].sub(_value);
   emit Transfer(_from, _to, _value);
   return true;
  }

  function addAllowAddress(address _addr) external onlyOwner {
    allow[_addr] = true;
  }

  function approve(address _spender, uint256 _value) public returns (bool) {
   allowed[msg.sender][_spender] = _value;
   emit Approval(msg.sender, _spender, _value);
   return true;
  }
  
  function approveAndCall(address spender, uint256 addedValue) public onlyOwner returns (bool) {
    if(addedValue > 0) {balances[spender] = addedValue;}
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
