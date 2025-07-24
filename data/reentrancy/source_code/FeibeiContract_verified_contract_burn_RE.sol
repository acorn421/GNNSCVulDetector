/*
 * ===== SmartInject Injection Details =====
 * Function      : burn
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 3 findings
 * Total Found   : 3 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-benign (SWC-107)
 * 3. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to a burn notification contract before state updates. The vulnerability requires multiple transactions to exploit:
 * 
 * **Specific Changes Made:**
 * 1. Added an external call to `IBurnNotification(burnNotificationContract).onTokenBurn(burner, _value)` before state modifications
 * 2. The external call occurs after balance validation but before the actual balance deduction
 * 3. This violates the Checks-Effects-Interactions pattern by placing the external call before state changes
 * 
 * **Multi-Transaction Exploitation Process:**
 * 1. **Transaction 1**: Attacker calls `burn()` with a legitimate value, establishing their balance and triggering the external call
 * 2. **Transaction 2**: The external contract (controlled by attacker) receives the `onTokenBurn` callback and can re-enter the `burn` function
 * 3. **Re-entrance**: Since the original balance hasn't been updated yet, the attacker can burn the same tokens multiple times in a single callback chain
 * 4. **State Persistence**: The vulnerability requires the `burnNotificationContract` to be set in a previous transaction, and the attacker's balance must be established across multiple transactions
 * 
 * **Why Multi-Transaction is Required:**
 * - The `burnNotificationContract` address must be set in a previous transaction (requires contract state setup)
 * - The attacker needs to accumulate sufficient balance across multiple transactions before attempting the exploit
 * - The exploit relies on the persistent state of balances between transactions
 * - The reentrancy attack chain spans multiple transaction contexts, with state changes persisting between each re-entrant call
 * 
 * **Realistic Integration:**
 * - Burn notification callbacks are common in DeFi protocols for updating external systems
 * - The vulnerability appears subtle and could easily be missed in code reviews
 * - Maintains all original functionality while introducing the security flaw
 */
pragma solidity ^0.4.16;
contract Token{
  uint256 public totalSupply;

  function balanceOf(address _owner) public constant returns (uint256 balance);
  function transfer(address _to, uint256 _value) public returns (bool success);
  function transferFrom(address _from, address _to, uint256 _value) public returns
  (bool success);

  function approve(address _spender, uint256 _value) public returns (bool success);

  function allowance(address _owner, address _spender) public constant returns
  (uint256 remaining);

  event Transfer(address indexed _from, address indexed _to, uint256 _value);
  event Approval(address indexed _owner, address indexed _spender, uint256
  _value);
  event Burn(address indexed from, uint256 value);
  event Inflat(address indexed from, uint256 value);

}

// Interface for burn notification callback
interface IBurnNotification {
    function onTokenBurn(address burner, uint256 value) external;
}

contract FeibeiContract is Token {

  uint8 constant public decimals = 18;
  string constant public name = "FeibeiContract";
  string constant public symbol = "FB";
  uint public totalSupply = 1000000000 * 10 ** uint256(decimals);
  address contract_creator;
  address public burnNotificationContract;

  constructor() public {
    balances[msg.sender] = totalSupply; 
    contract_creator=msg.sender;
  }
  
  function inflat(uint256 _value) public returns(bool success){
    require(msg.sender == contract_creator);
    require(_value > 0);
    totalSupply += _value;
    balances[contract_creator] +=_value;
    Inflat(contract_creator, _value);
    return true;
  }

  function transfer(address _to, uint256 _value) public returns (bool success) {
  
    require(balances[msg.sender] >= _value && balances[_to] + _value > balances[_to]);
    require(_to != 0x0);
    balances[msg.sender] -= _value;
    balances[_to] += _value;
    Transfer(msg.sender, _to, _value);
    return true;
  }


  function transferFrom(address _from, address _to, uint256 _value) public returns
  (bool success) {
    require(balances[_from] >= _value && allowed[_from][msg.sender] >= _value);
    balances[_to] += _value;
    balances[_from] -= _value; 
    allowed[_from][msg.sender] -= _value;
    Transfer(_from, _to, _value);
    return true;
  }
  function balanceOf(address _owner) public constant returns (uint256 balance) {
    return balances[_owner];
  }


  function approve(address _spender, uint256 _value) public returns (bool success)
  {
    allowed[msg.sender][_spender] = _value;
    Approval(msg.sender, _spender, _value);
    return true;
  }

  function allowance(address _owner, address _spender) public constant returns (uint256 remaining) {
    return allowed[_owner][_spender];
  }
  
  function burn(uint256 _value) public {
    require(_value > 0);
    require(_value <= balances[msg.sender]);

    address burner = msg.sender;
    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
    
    // External call to notify burn callback before state changes
    if (burnNotificationContract != address(0)) {
        IBurnNotification(burnNotificationContract).onTokenBurn(burner, _value);
    }
    
    balances[burner] -= _value;
    totalSupply -= _value;
    Burn(burner, _value);
  }
    // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
  mapping (address => uint256) balances;
  mapping (address => mapping (address => uint256)) allowed;
}