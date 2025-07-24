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
 * Introduced a multi-transaction reentrancy vulnerability by adding an external call to the recipient contract before completing all state updates. The vulnerability operates as follows:
 * 
 * **Specific Changes Made:**
 * 1. **Moved recipient balance update** to occur first, before the external call
 * 2. **Added external call** to `_to.call()` with `onTokenReceived` callback before sender's balance and allowance are updated
 * 3. **Placed critical state updates** (sender balance and allowance) after the external call
 * 
 * **Multi-Transaction Exploitation Pattern:**
 * 1. **Transaction 1**: Attacker calls `transferFrom()` with a malicious contract as `_to`
 * 2. **During Transaction 1**: The malicious contract's `onTokenReceived` callback is triggered
 * 3. **Transaction 2**: The callback triggers another `transferFrom()` call in a separate transaction
 * 4. **Exploitation**: Since the original sender's balance and allowance haven't been updated yet from Transaction 1, the second transaction can drain more tokens than allowed
 * 
 * **Why Multi-Transaction is Required:**
 * - The vulnerability requires the external call to trigger additional logic in a separate transaction context
 * - The incomplete state updates from the first transaction create conditions for exploitation in subsequent transactions
 * - The allowance mapping retains its original value during the callback, enabling over-spending across multiple calls
 * - Each transaction maintains its own execution context, but the contract state persists between calls
 * 
 * **Realistic Attack Scenario:**
 * An attacker could deploy a malicious contract that implements `onTokenReceived` to immediately call `transferFrom` again in a new transaction, effectively doubling the transfer amount while only consuming the allowance once due to the delayed state updates.
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
    balances[msg.sender] = balances[msg.sender].sub(_value);
    total_supply = total_supply.sub(_value);
    msg.sender.transfer(_value);
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
      emit Transfer(msg.sender, _to, _amount);
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
      // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
      
      // Update recipient balance first (enables multi-transaction reentrancy)
      balances[_to] = balances[_to].add(_amount);
      
      // External call to notify recipient before completing state updates
      // **Fixed for Solidity 0.4.x:** No `.code.length` member for address, must use a workaround
      if (isContract(_to)) {
        _to.call(abi.encodeWithSignature("onTokenReceived(address,address,uint256)", _from, msg.sender, _amount));
      }
      
      // State updates occur after external call (classic reentrancy pattern)
      // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
      balances[_from] = balances[_from].sub(_amount);
      allowed[_from][msg.sender] = allowed[_from][msg.sender].sub(_amount);
      // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
      
      // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
      emit Transfer(_from, _to, _amount);
      return true;
    } else {
      return false;
    }
  }

  //Approves a _spender an _amount of tokens to use
  function approve(address _spender, uint _amount) public returns (bool success) {
    allowed[msg.sender][_spender] = _amount;
    emit Approval(msg.sender, _spender, _amount);
    return true;
  }

  //Returns the remaining allowance of tokens granted to the _spender from the _owner
  function allowance(address _owner, address _spender) public view returns (uint remaining) { return allowed[_owner][_spender]; }

  // Helper function for address code check in 0.4.x
  function isContract(address _addr) internal view returns (bool is_contract) {
    uint length;
    assembly { length := extcodesize(_addr) }
    return length > 0;
  }
}
