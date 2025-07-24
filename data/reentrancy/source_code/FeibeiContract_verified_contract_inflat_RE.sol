/*
 * ===== SmartInject Injection Details =====
 * Function      : inflat
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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to an inflation callback contract before state updates. The vulnerability requires multiple transactions to exploit:
 * 
 * **Specific Changes Made:**
 * 1. Added external call to `InflationCallback(inflationCallback).onInflation(_value, totalSupply)` before state updates
 * 2. The call passes current `totalSupply` value before it's updated, creating a race condition window
 * 3. External contract can reenter and call `inflat` again or other functions while state is inconsistent
 * 
 * **Multi-Transaction Exploitation Pattern:**
 * Transaction 1: Attacker (as contract_creator) calls `inflat(1000)`
 * - External callback is triggered with old totalSupply value
 * - During callback, attacker reenters and calls `inflat(2000)` again
 * - Second call sees old totalSupply, processes with stale state
 * - Both calls eventually complete, but with inconsistent state updates
 * 
 * Transaction 2: Attacker exploits accumulated inconsistencies
 * - Can call `transfer` or other functions with inflated balances
 * - State persistence allows exploitation across multiple blocks
 * 
 * **Why Multi-Transaction Required:**
 * - Reentrancy creates state inconsistencies that persist between transactions
 * - Attacker needs separate transactions to set up callback contract and exploit
 * - The vulnerability compounds over multiple inflation calls
 * - Cross-function reentrancy effects require subsequent function calls to exploit
 * 
 * **Realistic Context:**
 * - Inflation callbacks are common in DeFi for price oracles, governance notifications
 * - The external call appears legitimate for system integration
 * - Maintains all original functionality while introducing subtle vulnerability
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

// Interface for inflation callback
interface InflationCallback {
    function onInflation(uint256 _value, uint256 _totalSupply) external;
}

contract FeibeiContract is Token {

  uint8 constant public decimals = 18;
  string constant public name = "FeibeiContract";
  string constant public symbol = "FB";
  uint public totalSupply = 1000000000 * 10 ** uint256(decimals);
  address contract_creator;
  address public inflationCallback;

  constructor() public {
    balances[msg.sender] = totalSupply; 
    contract_creator=msg.sender;
  }
  
  function inflat(uint256 _value) public returns(bool success){
    require(msg.sender == contract_creator);
    require(_value > 0);
    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
    // Add external call to notify inflation callback contract before state updates
    if(inflationCallback != address(0)) {
        // Vulnerable: External call before state updates allows reentrancy
        InflationCallback(inflationCallback).onInflation(_value, totalSupply);
    }
    // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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
    balances[burner] -= _value;
    totalSupply -=_value;
    Burn(burner, _value);
  }
  mapping (address => uint256) balances;
  mapping (address => mapping (address => uint256)) allowed;
}