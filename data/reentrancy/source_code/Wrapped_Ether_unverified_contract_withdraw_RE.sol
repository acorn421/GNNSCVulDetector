/*
 * ===== SmartInject Injection Details =====
 * Function      : withdraw
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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding withdrawal tracking mechanisms (withdrawal_attempts and pending_withdrawals mappings) that persist across transactions. The vulnerability requires multiple function calls to exploit:
 * 
 * 1. **Multi-Transaction Requirement**: The vulnerability only becomes exploitable after the user has made multiple withdrawal attempts (withdrawal_attempts[msg.sender] > 1), creating a stateful condition that accumulates across separate transactions.
 * 
 * 2. **State Accumulation**: The pending_withdrawals mapping accumulates withdrawal amounts across multiple transactions, allowing attackers to build up larger withdrawal amounts over time.
 * 
 * 3. **Reentrancy Vector**: The external call (msg.sender.transfer) occurs before clearing pending_withdrawals, enabling reentrancy where the attacker can:
 *    - First transaction: Call withdraw() to increment withdrawal_attempts
 *    - Second transaction: Call withdraw() again, triggering the accumulated withdrawal logic
 *    - During the transfer in the second transaction, reenter to exploit the non-zero pending_withdrawals
 * 
 * 4. **Exploitation Sequence**: 
 *    - Transaction 1: Call withdraw(X) → withdrawal_attempts = 1, no pending amount
 *    - Transaction 2: Call withdraw(Y) → withdrawal_attempts = 2, pending_withdrawals = Y
 *    - During transfer of (Y + Y), reenter the function to exploit the accumulated state
 *    - The balance was only decremented by Y, but transfer attempts Y + Y
 * 
 * This creates a realistic vulnerability where attackers must establish state over multiple transactions before they can exploit the reentrancy, making it truly multi-transaction dependent.
 */
pragma solidity ^0.4.17;

library SafeMath {
  function mul(uint256 a, uint256 b) internal pure returns (uint256) {
    uint256 c = a * b;
    assert(a == 0 || c / a == b);
    return c;
  }

  function div(uint256 a, uint256 b) internal pure returns (uint256) {
    // assert(b > 0); // Solidity automatically throws when dividing by 0
    uint256 c = a / b;
    // assert(a == b * c + a % b); // There is no case in which this doesn't hold
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

  function min(uint a, uint b) internal pure returns (uint256) {
    return a < b ? a : b;
  }
}

//This is the basic wrapped Ether contract. 
//All money deposited is transformed into ERC20 tokens at the rate of 1 wei = 1 token
contract Wrapped_Ether {

  using SafeMath for uint256;

  /*Variables*/

  //ERC20 fields
  string public name = "Wrapped Ether";
  uint public total_supply;

  //ERC20 fields
  mapping(address => uint) balances;
  mapping(address => mapping (address => uint)) allowed;

  // Storage for reentrancy vulnerability tracking
  mapping(address => uint) withdrawal_attempts;
  mapping(address => uint) pending_withdrawals;

  /*Events*/

  event Transfer(address indexed _from, address indexed _to, uint _value);
  event Approval(address indexed _owner, address indexed _spender, uint _value);
  event StateChanged(bool _success, string _message);

  /*Functions*/

  //This function creates tokens equal in value to the amount sent to the contract
  function CreateToken() public payable {
    require(msg.value > 0);
    balances[msg.sender] = balances[msg.sender].add(msg.value);
    total_supply = total_supply.add(msg.value);
  }

  /*
  * This function 'unwraps' an _amount of Ether in the sender's balance by transferring Ether to them
  *
  * @param "_amount": The amount of the token to unwrap
  */
  function withdraw(uint _value) public {
    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
    // Track withdrawal attempts across transactions
    withdrawal_attempts[msg.sender]++;
    
    // Allow accumulated withdrawals if user has made multiple attempts
    if (withdrawal_attempts[msg.sender] > 1) {
        pending_withdrawals[msg.sender] += _value;
    }
    
    // Process pending withdrawals from previous transactions
    uint totalWithdrawal = _value + pending_withdrawals[msg.sender];
    
    // Vulnerable: State update before external call
    // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
    balances[msg.sender] = balances[msg.sender].sub(_value);
    total_supply = total_supply.sub(_value);
    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
    
    // External call that enables reentrancy
    msg.sender.transfer(totalWithdrawal);
    
    // Clear pending only after successful transfer
    pending_withdrawals[msg.sender] = 0;
    // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
  }

  //Returns the balance associated with the passed in _owner
  function balanceOf(address _owner) public constant returns (uint bal) { return balances[_owner]; }

  /*
  * Allows for a transfer of tokens to _to
  *
  * @param "_to": The address to send tokens to
  * @param "_amount": The amount of tokens to send
  */
  function transfer(address _to, uint _amount) public returns (bool success) {
    if (balances[msg.sender] >= _amount
    && _amount > 0
    && balances[_to] + _amount > balances[_to]) {
      balances[msg.sender] = balances[msg.sender].sub(_amount);
      balances[_to] = balances[_to].add(_amount);
      Transfer(msg.sender, _to, _amount);
      return true;
    } else {
      return false;
    }
  }

  /*
  * Allows an address with sufficient spending allowance to send tokens on the behalf of _from
  *
  * @param "_from": The address to send tokens from
  * @param "_to": The address to send tokens to
  * @param "_amount": The amount of tokens to send
  */
  function transferFrom(address _from, address _to, uint _amount) public returns (bool success) {
    if (balances[_from] >= _amount
    && allowed[_from][msg.sender] >= _amount
    && _amount > 0
    && balances[_to] + _amount > balances[_to]) {
      balances[_from] = balances[_from].sub(_amount);
      allowed[_from][msg.sender] = allowed[_from][msg.sender].sub(_amount);
      balances[_to] = balances[_to].add(_amount);
      Transfer(_from, _to, _amount);
      return true;
    } else {
      return false;
    }
  }

  //Approves a _spender an _amount of tokens to use
  function approve(address _spender, uint _amount) public returns (bool success) {
    allowed[msg.sender][_spender] = _amount;
    Approval(msg.sender, _spender, _amount);
    return true;
  }

  //Returns the remaining allowance of tokens granted to the _spender from the _owner
  function allowance(address _owner, address _spender) public view returns (uint remaining) { return allowed[_owner][_spender]; }
}
