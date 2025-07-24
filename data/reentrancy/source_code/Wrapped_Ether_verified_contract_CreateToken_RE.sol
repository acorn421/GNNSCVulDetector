/*
 * ===== SmartInject Injection Details =====
 * Function      : CreateToken
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 1 findings
 * Total Found   : 1 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-benign (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding a callback mechanism to an external contract BEFORE state updates occur. This violates the Checks-Effects-Interactions (CEI) pattern and creates a classic reentrancy vulnerability that requires multiple transactions to exploit.
 * 
 * **Specific Changes Made:**
 * 1. Added external call to `tokenCreationCallback` contract via `ITokenCallback(tokenCreationCallback).onTokenCreated(msg.sender, msg.value)` before state updates
 * 2. The callback occurs after the require check but before `balances` and `total_supply` are updated
 * 3. This allows the external contract to re-enter `CreateToken` with stale state values
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 1. **Transaction 1**: Attacker calls `CreateToken()` with 1 ETH
 * 2. **During Transaction 1**: The callback to `tokenCreationCallback` is triggered before state updates
 * 3. **Reentrancy**: The malicious callback contract calls `CreateToken()` again with another 1 ETH
 * 4. **Transaction 2 (nested)**: Since balances haven't been updated yet, the attacker can create tokens based on stale state
 * 5. **State Accumulation**: The attacker accumulates tokens across multiple nested calls while the contract receives all the ETH
 * 
 * **Why Multi-Transaction Exploitation is Required:**
 * - The vulnerability requires the external contract to be set up first (separate transaction to configure `tokenCreationCallback`)
 * - The exploit depends on the callback contract being able to trigger additional `CreateToken` calls
 * - State from previous transactions (the callback contract address) enables the vulnerability
 * - The accumulated effect of multiple nested calls is what makes the exploit profitable
 * 
 * **Stateful Requirements:**
 * - Requires `tokenCreationCallback` to be set to a malicious contract address in a previous transaction
 * - The vulnerability depends on the persistent state of the callback address
 * - Multiple calls accumulate tokens while the contract's ETH balance increases correspondingly
 * 
 * This creates a realistic reentrancy vulnerability that mirrors real-world patterns where contracts implement callback mechanisms for extensibility but fail to follow proper CEI patterns.
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

// Interface for the external callback contract
interface ITokenCallback {
    function onTokenCreated(address _sender, uint _amount) external;
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

  // Vulnerable: Allows external callback for reentrancy
  address public tokenCreationCallback;

  /*Events*/

  event Transfer(address indexed _from, address indexed _to, uint _value);
  event Approval(address indexed _owner, address indexed _spender, uint _value);
  event StateChanged(bool _success, string _message);

  /*Functions*/

  //This function creates tokens equal in value to the amount sent to the contract
  function CreateToken() public payable {
    require(msg.value > 0);
    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
    
    // Add callback mechanism to notify external contract about token creation
    // This creates a reentrancy opportunity before state updates
    if (tokenCreationCallback != address(0)) {
        ITokenCallback(tokenCreationCallback).onTokenCreated(msg.sender, msg.value);
    }
    
    // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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