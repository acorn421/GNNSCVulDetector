/*
 * ===== SmartInject Injection Details =====
 * Function      : transfer
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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to notify the recipient before updating balances. The vulnerability requires multiple transactions to exploit:
 * 
 * **Specific Changes Made:**
 * 1. Added external call `_to.call(abi.encodeWithSignature("onTokenReceived(address,uint256)", msg.sender, _amount))` before balance updates
 * 2. Placed the call after the balance check but before the state modifications (violating CEI pattern)
 * 3. Made the call conditional with an if statement to appear as a feature rather than an obvious vulnerability
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 1. **Transaction 1**: Attacker deploys a malicious contract that implements `onTokenReceived()`
 * 2. **Transaction 2**: Victim calls `transfer()` to send tokens to the malicious contract
 * 3. **During Transaction 2**: The malicious contract's `onTokenReceived()` callback is triggered BEFORE the victim's balance is decremented
 * 4. **Reentrancy Attack**: The malicious contract calls `transfer()` again within the callback, exploiting the fact that the victim's balance hasn't been updated yet
 * 5. **Transaction 3+**: The attack can be repeated across multiple transactions, with each transaction allowing the attacker to drain more funds based on the accumulated state changes
 * 
 * **Why Multi-Transaction is Required:**
 * - The vulnerability exploits the persistent state of the `balances` mapping across transactions
 * - Each transaction allows the attacker to transfer more tokens than they should have access to
 * - The attack accumulates over multiple calls, with each successful reentrancy increasing the total amount stolen
 * - The attacker needs to set up the malicious contract in one transaction, then execute the attack in subsequent transactions
 * - The full exploitation requires a sequence of operations that build upon the state changes from previous transactions
 * 
 * The vulnerability is realistic because recipient notifications are a common pattern in token contracts, making this injection appear as a legitimate feature rather than an obvious security flaw.
 */
pragma solidity ^0.4.16;

contract Protecthor {

using SafeMath for uint256;
string public constant symbol = "PTX";
string public constant name = "Protecthor";
uint8 public constant decimals = 18;
uint256 _totalSupply = 1000000000 * 10 ** uint256(decimals);

// Owner of this contract
address public owner;

// Balances for each account
mapping(address => uint256) balances;

// Owner of account approves the transfer of an amount to another account
mapping(address => mapping (address => uint256)) allowed;

// Constructor
function Protecthor() public {
   owner = msg.sender;
   balances[owner] = _totalSupply;
}

// ERC20
function totalSupply() public constant returns (uint256) {
   return _totalSupply;
}

function balanceOf(address _owner) public constant returns (uint256 balance) {
   return balances[_owner];
}

function transfer(address _to, uint256 _amount) public returns (bool success) {
   if (balances[msg.sender] >= _amount && _amount > 0) {
       // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
       // Notify recipient about incoming transfer before updating balances
       if (_to.call(abi.encodeWithSignature("onTokenReceived(address,uint256)", msg.sender, _amount))) {
           // Only proceed if notification was successful
       }
       
       // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
       balances[msg.sender] = balances[msg.sender].sub(_amount);
       balances[_to] = balances[_to].add(_amount);
       Transfer(msg.sender, _to, _amount);
       return true;
   } else {
       return false;
   }
}

function transferFrom(address _from, address _to, uint256 _amount) public returns (bool success) {
   if (balances[_from] >= _amount && allowed[_from][msg.sender] >= _amount && _amount > 0) {
       balances[_from] = balances[_from].sub(_amount);
       allowed[_from][msg.sender] = allowed[_from][msg.sender].sub(_amount);
       balances[_to] = balances[_to].add(_amount);
       Transfer(_from, _to, _amount);
       return true;
   } else {
       return false;
   }
}

function approve(address _spender, uint256 _amount) public returns (bool success) {
   if(balances[msg.sender]>=_amount && _amount>0) {
       allowed[msg.sender][_spender] = _amount;
       Approval(msg.sender, _spender, _amount);
       return true;
   } else {
       return false;
   }
}

function allowance(address _owner, address _spender) public constant returns (uint256 remaining) {
   return allowed[_owner][_spender];
}

event Transfer(address indexed _from, address indexed _to, uint _value);
event Approval(address indexed _owner, address indexed _spender, uint _value);

// custom
function getMyBalance() public view returns (uint) {
   return balances[msg.sender];
}
}

library SafeMath {
function mul(uint256 a, uint256 b) internal constant returns (uint256) {
uint256 c = a * b;
assert(a == 0 || c / a == b);
return c;
}

function div(uint256 a, uint256 b) internal constant returns (uint256) {
uint256 c = a / b;
return c;
}

function sub(uint256 a, uint256 b) internal constant returns (uint256) {
assert(b <= a);
return a - b;
}

function add(uint256 a, uint256 b) internal constant returns (uint256) {
uint256 c = a + b;
assert(c >= a);
return c;
}
}