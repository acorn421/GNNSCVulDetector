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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the recipient (_to) address before completing all state updates. The vulnerability works as follows:
 * 
 * **Specific Changes Made:**
 * 1. Added external call to `_to.call()` with `onTokenReceived` signature between balance updates
 * 2. The call occurs after `balances[_to] += _value` but before `balances[_from] -= _value` and `allowed[_from][msg.sender] -= _value`
 * 3. This violates the Checks-Effects-Interactions (CEI) pattern by performing external interaction before completing state changes
 * 
 * **Multi-Transaction Exploitation Process:**
 * 1. **Setup Phase (Transaction 1)**: Attacker deploys a malicious contract and gets approval from a victim to spend tokens
 * 2. **Exploitation Phase (Transaction 2+)**: Attacker calls transferFrom, triggering the external call to their malicious contract
 * 3. **Reentrant Calls**: The malicious contract's onTokenReceived function calls transferFrom again before the original call completes
 * 4. **State Accumulation**: Each reentrant call can exploit the same allowance since `allowed[_from][msg.sender] -= _value` hasn't executed yet
 * 5. **Multi-Transaction Continuation**: The attack can span multiple transactions, with each transaction building on the state changes from previous ones
 * 
 * **Why Multi-Transaction is Required:**
 * - The vulnerability requires pre-existing allowance state set up in previous transactions
 * - Attackers need to deploy malicious contracts and establish relationships before exploitation
 * - The attack leverages accumulated state changes across multiple function calls
 * - Each transaction in the attack sequence depends on the state modifications from previous transactions
 * - The allowance system inherently requires multi-transaction setup (approve, then transferFrom)
 * 
 * **Realistic Vulnerability Pattern:**
 * This mimics real-world token standards that implement transfer hooks or recipient notifications, making it a realistic vulnerability that could appear in production code attempting to provide enhanced functionality.
 */
pragma solidity ^0.4.16;
contract Token {
  uint256 public totalSupply;

  mapping (address => uint256) balances;
  mapping (address => mapping (address => uint256)) allowed;

  function balanceOf(address _owner) public constant returns (uint256 balance);
  function transfer(address _to, uint256 _value) public returns (bool success);
  function transferFrom(address _from, address _to, uint256 _value) public returns
  (bool success) {
    require(balances[_from] >= _value && allowed[_from][msg.sender] >= _value);
    balances[_to] += _value;
    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
    // Notify recipient contract about token transfer (potential reentrancy point)
    if (_to.call.gas(2300)(abi.encodeWithSignature("onTokenReceived(address,address,uint256)", _from, msg.sender, _value))) {
        // External call succeeded, continue with state updates
    }
    // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
    balances[_from] -= _value;
    allowed[_from][msg.sender] -= _value;
    Transfer(_from, _to, _value);
    return true;
  }

  function approve(address _spender, uint256 _value) public returns (bool success);

  function allowance(address _owner, address _spender) public constant returns
  (uint256 remaining);

  event Transfer(address indexed _from, address indexed _to, uint256 _value);
  event Approval(address indexed _owner, address indexed _spender, uint256
  _value);
  event Burn(address indexed from, uint256 value);
  event Inflat(address indexed from, uint256 value);
}

contract FeibeiContract is Token {
  uint8 constant public decimals = 18;
  string constant public name = "FeibeiContract";
  string constant public symbol = "FB";
  uint public totalSupply = 1000000000 * 10 ** uint256(decimals);
  address contract_creator;

  function FeibeiContract() public {
    balances[msg.sender] = totalSupply; 
    contract_creator = msg.sender;
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
    balances[burner] -= _value;
    totalSupply -=_value;
    Burn(burner, _value);
  }
}