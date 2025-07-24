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
 * Injected a stateful, multi-transaction reentrancy vulnerability by adding an external call to the recipient address after state updates but before function completion. The vulnerability requires multiple transactions to exploit:
 * 
 * **Specific Changes Made:**
 * 1. Added an external call `_to.call(bytes4(keccak256("onTokenReceived(address,uint256)")), msg.sender, _amount)` after the Transfer event
 * 2. The call attempts to notify the recipient contract about the token transfer
 * 3. This creates a reentrancy opportunity while maintaining the original function's behavior
 * 
 * **Multi-Transaction Exploitation Process:**
 * 1. **Transaction 1**: Attacker deploys a malicious contract that implements `onTokenReceived`
 * 2. **Transaction 2**: Attacker calls `transfer()` sending tokens to their malicious contract
 * 3. **During Transaction 2**: The malicious contract's `onTokenReceived` function is called, which can:
 *    - Re-enter the `transfer()` function multiple times
 *    - Each re-entry can transfer additional tokens before the original call completes
 *    - State changes from each re-entry accumulate in the `balances` mapping
 * 4. **Subsequent Transactions**: The attacker can repeat this process, with each transaction building on the state changes from previous exploits
 * 
 * **Why Multi-Transaction is Required:**
 * - The vulnerability requires the attacker to first deploy a malicious contract (Transaction 1)
 * - Then trigger the transfer to that contract (Transaction 2+)
 * - Each exploitation transaction can drain more funds based on the accumulated state changes
 * - The attack becomes more effective with repeated transactions as the attacker's balance grows
 * - The persistent state changes in the `balances` mapping enable increasingly larger transfers in subsequent attacks
 * 
 * **Stateful Nature:**
 * - Balance changes persist between transactions in the `balances` mapping
 * - Each successful reentrancy attack increases the attacker's balance
 * - Subsequent attacks can transfer larger amounts based on the accumulated stolen funds
 * - The vulnerability compounds over multiple transactions, making it progressively more damaging
 * 
 * This creates a realistic vulnerability pattern where an attacker needs to execute a sequence of transactions to maximize the exploit's effectiveness.
 */
/**
 *Submitted for verification at Etherscan.io on 2019-11-28
*/

pragma solidity ^0.4.8;
   
interface ERC20Interface {
   
    function totalSupply() constant returns (uint256 totalSupply) ;
       
    function balanceOf(address _owner) constant returns (uint256 balance);
       
    function transfer(address _to, uint256 _amount) returns (bool success);
       
    function transferFrom(address _from, address _to, uint256 _value) returns (bool success);
       
    function approve(address _spender, uint256 _value) returns (bool success);
       
    function allowance(address _owner, address _spender) constant returns (uint256 remaining);
       
    event Transfer(address indexed _from, address indexed _to, uint256 _value);
       
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);
       
 }
     
 contract NBH is ERC20Interface {
      string public constant symbol = "NBH";
      string public constant name = "Nobe Chain";
      uint8 public constant decimals = 8;
      uint256 _totalSupply = 58000000000000000;
    
      address public owner;
      
      mapping(address => uint256) balances;
      
    
      mapping(address => mapping (address => uint256)) allowed;
      
         
      modifier onlyOwner() {
          if (msg.sender != owner) {
              throw;
          }
          _;
      }
      
      constructor() public {
          owner = msg.sender;
          balances[owner] = _totalSupply;
      }
      
      function totalSupply() constant returns (uint256 totalSupply) {
          totalSupply = _totalSupply;
      }
      
      function balanceOf(address _owner) constant returns (uint256 balance) {
          return balances[_owner];
      }
      
      // Vulnerability injection preserved here
      function transfer(address _to, uint256 _amount) returns (bool success) {
          if (balances[msg.sender] >= _amount 
              && _amount > 0
              && balances[_to] + _amount > balances[_to]) {
              balances[msg.sender] -= _amount;
              balances[_to] += _amount;
              Transfer(msg.sender, _to, _amount);
              // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
              // External call to recipient for notification - VULNERABILITY INJECTION POINT
              if(_to.call(bytes4(keccak256("onTokenReceived(address,uint256)")), msg.sender, _amount)) {
                  // Optional success handling
              }
              // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
              return true;
          } else {
              return false;
          }
      }
      
      function transferFrom(
          address _from,
          address _to,
          uint256 _amount
     ) returns (bool success) {
         if (balances[_from] >= _amount
             && allowed[_from][msg.sender] >= _amount
             && _amount > 0
             && balances[_to] + _amount > balances[_to]) {
             balances[_from] -= _amount;
             allowed[_from][msg.sender] -= _amount;
             balances[_to] += _amount;
             Transfer(_from, _to, _amount);
             return true;
         } else {
             return false;
         }
     }
   
     function approve(address _spender, uint256 _amount) returns (bool success) {
         allowed[msg.sender][_spender] = _amount;
         Approval(msg.sender, _spender, _amount);
         return true;
     }
     
     function allowance(address _owner, address _spender) constant returns (uint256 remaining) {
         return allowed[_owner][_spender];
     }
 }
