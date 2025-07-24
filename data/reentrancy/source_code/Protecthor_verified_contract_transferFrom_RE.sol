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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the recipient address (_to) for transfer notifications. The vulnerability is positioned after the sender's balance is deducted but before the allowance is updated and the recipient's balance is credited. This creates a window where the contract state is inconsistent and can be exploited through multiple transactions.
 * 
 * **Specific Changes Made:**
 * 1. Added an external call to `_to.call()` after deducting the sender's balance
 * 2. The call is made before updating the allowance and crediting the recipient's balance
 * 3. Added a check for contract code to ensure the call is only made to contracts
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 1. **Transaction 1**: Attacker sets up allowances and deploys a malicious contract
 * 2. **Transaction 2**: Victim calls `transferFrom()` with the malicious contract as recipient
 * 3. **During Transaction 2**: The malicious contract's `onTokenReceived()` is called, which can:
 *    - Reenter `transferFrom()` while the original allowance is still high
 *    - Drain additional funds because the allowance hasn't been decremented yet
 *    - Exploit the inconsistent state where sender's balance is reduced but allowance remains high
 * 
 * **Why Multiple Transactions Are Required:**
 * - The vulnerability requires prior setup of allowances (approve() calls in earlier transactions)
 * - The attacker must deploy and position a malicious contract to receive the callback
 * - The exploitation depends on accumulated allowances from previous transactions
 * - The reentrancy attack builds upon the state established in prior transactions, making it inherently multi-transaction
 * 
 * **State Persistence Elements:**
 * - The `allowed` mapping persists between transactions and is crucial for the exploit
 * - The `balances` mapping maintains state that can be manipulated across multiple calls
 * - The attacker can accumulate allowances over time and then exploit them in a coordinated attack
 * 
 * This vulnerability is realistic as it mimics real-world token transfer notification patterns while introducing a critical timing vulnerability that requires multiple transactions to exploit effectively.
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
constructor() public {
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
       balances[msg.sender] = balances[msg.sender].sub(_amount);
       balances[_to] = balances[_to].add(_amount);
       emit Transfer(msg.sender, _to, _amount);
       return true;
   } else {
       return false;
   }
}

function transferFrom(address _from, address _to, uint256 _amount) public returns (bool success) {
   if (balances[_from] >= _amount && allowed[_from][msg.sender] >= _amount && _amount > 0) {
       balances[_from] = balances[_from].sub(_amount);
       // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
       // External call to recipient for transfer notification - VULNERABILITY: Reentrancy point
       if (isContract(_to)) {
           _to.call(abi.encodeWithSignature("onTokenReceived(address,address,uint256)", _from, msg.sender, _amount));
       }
       // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
       allowed[_from][msg.sender] = allowed[_from][msg.sender].sub(_amount);
       balances[_to] = balances[_to].add(_amount);
       emit Transfer(_from, _to, _amount);
       return true;
   } else {
       return false;
   }
}

function approve(address _spender, uint256 _amount) public returns (bool success) {
   if(balances[msg.sender]>=_amount && _amount>0) {
       allowed[msg.sender][_spender] = _amount;
       emit Approval(msg.sender, _spender, _amount);
       return true;
   } else {
       return false;
   }
}

function allowance(address _owner, address _spender) public constant returns (uint256 remaining) {
   return allowed[_owner][_spender];
}

// Helper function to check if an address is a contract
function isContract(address _addr) internal view returns (bool) {
    uint256 length;
    assembly {
        length := extcodesize(_addr)
    }
    return (length > 0);
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