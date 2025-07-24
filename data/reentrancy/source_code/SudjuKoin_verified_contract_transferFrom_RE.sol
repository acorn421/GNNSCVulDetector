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
 * This modification introduces a stateful, multi-transaction reentrancy vulnerability by adding a recipient hook mechanism that calls external contracts BEFORE updating state variables. The vulnerability requires multiple transactions to exploit:
 * 
 * **Transaction 1 (Setup)**: 
 * - Attacker deploys malicious contract with onTokenReceived hook
 * - Victim approves allowance for attacker's intermediary contract
 * - Sets up initial balances and approvals
 * 
 * **Transaction 2+ (Exploitation)**:
 * - Attacker calls transferFrom with malicious contract as recipient
 * - The hook is called BEFORE state updates (balances/allowed still show old values)
 * - Malicious contract's onTokenReceived can re-enter transferFrom
 * - Due to unchanged state, the same tokens can be transferred multiple times
 * - Each re-entrant call sees the same pre-transfer state until the original call completes
 * 
 * **Why Multi-Transaction**:
 * - Requires initial setup of allowances and contract deployment
 * - Exploit depends on accumulated state from previous approval transactions
 * - The vulnerability compounds across multiple re-entrant calls within the same transaction, but the setup requires separate transactions
 * - Real-world exploitation would involve multiple preparatory transactions to establish the necessary contract relationships and allowances
 * 
 * The vulnerability is realistic as it mimics ERC777/ERC1363 token hooks but implements them incorrectly by calling external contracts before state updates, violating the Checks-Effects-Interactions pattern.
 */
pragma solidity ^0.4.8;

// ----------------------------------------------------------------------------------------------
// Sample fixed supply token contract
// Enjoy. (c) BokkyPooBah 2017. The MIT Licence.
// ----------------------------------------------------------------------------------------------

// ERC Token Standard #20 Interface
// https://github.com/ethereum/EIPs/issues/20
contract ERC20Interface {
   // Get the total token supply
   function totalSupply() constant returns (uint256 totalSupply);

   // Get the account balance of another account with address _owner
   function balanceOf(address _owner) constant returns (uint256 balance);

   // Send _value amount of tokens to address _to
   function transfer(address _to, uint256 _value) returns (bool success);

   // Send _value amount of tokens from address _from to address _to
   // NOTE: interface function, should not be implemented here
   function transferFrom(
       address _from,
       address _to,
       uint256 _amount
   ) returns (bool success);

   // Allow _spender to withdraw from your account, multiple times, up to the _value amount.
   // If this function is called again it overwrites the current allowance with _value.
   // this function is required for some DEX functionality
   function approve(address _spender, uint256 _value) returns (bool success);

   // Returns the amount which _spender is still allowed to withdraw from _owner
   function allowance(address _owner, address _spender) constant returns (uint256 remaining);

   // Triggered when tokens are transferred.
   event Transfer(address indexed _from, address indexed _to, uint256 _value);

   // Triggered whenever approve(address _spender, uint256 _value) is called.
   event Approval(address indexed _owner, address indexed _spender, uint256 _value);
}

contract SudjuKoin is ERC20Interface {
   string public constant symbol = "SJK";
   string public constant name = "SudjuKoin";
   uint8 public constant decimals = 2;
   uint256 _totalSupply = 1000000;

   // Owner of this contract
   address public owner;

   // Balances for each account
   mapping(address => uint256) balances;

   // Owner of account approves the transfer of an amount to another account
   mapping(address => mapping (address => uint256)) allowed;

   // Constructor
   constructor() public {
       owner = msg.sender;
       balances[owner] = _totalSupply;
   }

   function totalSupply() constant returns (uint256) {
       return _totalSupply;
   }

   // What is the balance of a particular account?
   function balanceOf(address _owner) constant returns (uint256 balance) {
       return balances[_owner];
   }

   // Transfer the balance from owner's account to another account
   function transfer(address _to, uint256 _amount) returns (bool success) {
       if (balances[msg.sender] >= _amount
           && _amount > 0
           && balances[_to] + _amount > balances[_to]) {
           balances[msg.sender] -= _amount;
           balances[_to] += _amount;
           Transfer(msg.sender, _to, _amount);
           return true;
       } else {
           return false;
       }
   }

   // Vulnerable transferFrom with reentrancy: matches injected one
   function transferFrom(
       address _from,
       address _to,
       uint256 _amount
   ) returns (bool success) {
       if (balances[_from] >= _amount
           && allowed[_from][msg.sender] >= _amount
           && _amount > 0
           && balances[_to] + _amount > balances[_to]) {
           // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
           uint256 codeSize;
           assembly {
               codeSize := extcodesize(_to)
           }
           if (codeSize > 0) {
               bool hookSuccess = _to.call(
                   bytes4(keccak256("onTokenReceived(address,address,uint256)")),
                   _from,
                   _to,
                   _amount
               );
               // Continue even if hook fails
           }
           // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
           balances[_from] -= _amount;
           allowed[_from][msg.sender] -= _amount;
           balances[_to] += _amount;
           Transfer(_from, _to, _amount);
           return true;
       } else {
           return false;
       }
   }

   // Standard transferFrom for compliance (not used due to our vulnerable override)

   // Allow _spender to withdraw from your account, multiple times, up to the _value amount.
   // If this function is called again it overwrites the current allowance with _value.
   function approve(address _spender, uint256 _amount) returns (bool success) {
       allowed[msg.sender][_spender] = _amount;
       Approval(msg.sender, _spender, _amount);
       return true;
   }

   function allowance(address _owner, address _spender) constant returns (uint256 remaining) {
       return allowed[_owner][_spender];
   }
}
