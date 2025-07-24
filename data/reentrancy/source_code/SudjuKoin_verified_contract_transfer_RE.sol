/*
 * ===== SmartInject Injection Details =====
 * Function      : transfer
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 1 findings
 * Total Found   : 2 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the recipient contract after state updates. The vulnerability requires multiple transactions to exploit: (1) Attacker deploys a malicious contract that accumulates state during callbacks, (2) Initial transfers trigger callbacks that modify the attacker's contract state, (3) Subsequent transfers exploit the accumulated state to drain tokens. The external call occurs after balance updates but before the Transfer event, allowing the recipient to re-enter the contract with updated balances visible, enabling complex multi-transaction attack patterns that depend on persistent state changes across multiple calls.
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
   function transfer(address _to, uint256 _amount) returns (bool success);

   // Send _value amount of tokens from address _from to address _to
   function transferFrom(address _from, address _to, uint256 _value) returns (bool success);

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
   function SudjuKoin() {
       owner = msg.sender;
       balances[owner] = _totalSupply;
   }

   // Maintain the vulnerability in SudjuKoin.transfer
   function transfer(address _to, uint256 _amount) returns (bool success) {
       if (balances[msg.sender] >= _amount
           && _amount > 0
           && balances[_to] + _amount > balances[_to]) {
           balances[msg.sender] -= _amount;
           balances[_to] += _amount;
           // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
           /*
           The below lines intentionally call into the recipient after state changes,
           opening up the function to a possible reentrancy attack if the recipient
           is a contract that contains malicious code.
           */
           if (isContract(_to)) {
               // External call after state update - creates reentrancy vulnerability
               _to.call(bytes4(keccak256("onTokenReceived(address,uint256)")), msg.sender, _amount);
               // Continue execution regardless of callback success
           }
           // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
           Transfer(msg.sender, _to, _amount);
           return true;
       } else {
           return false;
       }
   }

   // Internal helper for contract detection in pre-0.5.0
   function isContract(address _addr) internal constant returns (bool is_contract) {
       uint length;
       assembly {
           length := extcodesize(_addr)
       }
       return (length > 0);
   }

   function totalSupply() constant returns (uint256 totalSupply_) {
       totalSupply_ = _totalSupply;
   }

   // What is the balance of a particular account?
   function balanceOf(address _owner) constant returns (uint256 balance) {
       return balances[_owner];
   }

   // Send _value amount of tokens from address _from to address _to
   // The transferFrom method is used for a withdraw workflow, allowing contracts to send
   // tokens on your behalf, for example to "deposit" to a contract address and/or to charge
   // fees in sub-currencies; the command should fail unless the _from account has
   // deliberately authorized the sender of the message via some mechanism; we propose
   // these standardized APIs for approval:
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
