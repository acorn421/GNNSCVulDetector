/*
 * ===== SmartInject Injection Details =====
 * Function      : multiplyTokensSend
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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to recipient contracts after balance updates but before sender balance deduction. The vulnerability requires multiple transactions to exploit:
 * 
 * **Specific Changes Made:**
 * 1. Added external call to recipient addresses using `_addresses[i].call()` with `onTokenReceived` callback
 * 2. External call occurs after recipient balance is updated but before sender balance is deducted
 * 3. No reentrancy protection around the external call
 * 4. Call executes for any address with contract code
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 1. **Setup Transaction**: Attacker deploys malicious contract and calls `multiplyTokensSend` with their contract as recipient
 * 2. **Exploitation Transactions**: In subsequent calls to `multiplyTokensSend`, the malicious contract's `onTokenReceived` callback can:
 *    - Call `multiplyTokensSend` again during the callback
 *    - Manipulate the state between balance updates and sender deduction
 *    - Accumulate tokens across multiple reentrancy calls before the sender's balance is properly deducted
 * 
 * **Why Multi-Transaction is Required:**
 * - The vulnerability relies on building up state changes across multiple calls
 * - Each reentrancy call adds to recipient balances without immediately deducting from sender
 * - The exploit requires coordinated timing across multiple transactions to drain sender funds
 * - Single-transaction exploitation is limited by gas constraints and the need to establish attack conditions
 * 
 * **State Dependencies:**
 * - Attacker must first establish their malicious contract as a recipient
 * - Subsequent transactions can exploit the accumulated state changes
 * - The vulnerability compounds across multiple calls, making it more severe with repeated exploitation
 * 
 * This creates a realistic vulnerability that mirrors real-world token callback patterns while requiring sophisticated multi-transaction exploitation techniques.
 */
//standart library for uint
pragma solidity ^0.4.21;
library SafeMath { 
  function mul(uint256 a, uint256 b) internal pure returns (uint256) {
    if (a == 0 || b == 0){
        return 0;
    }
    uint256 c = a * b;
    assert(c / a == b);
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
}

contract Ownable {

  address public owner;

  address public newOwner;

  modifier onlyOwner() {
    require(msg.sender == owner);
    _;
  }

  constructor() public {
    owner = msg.sender;
  }

  function transferOwnership(address _newOwner) public onlyOwner {
    require(_newOwner != address(0));
    newOwner = _newOwner;
  }

  function acceptOwnership() public {
    if (msg.sender == newOwner) {
      owner = newOwner;
    }
  }
}

contract BidiumToken is Ownable { //ERC - 20 token contract
  using SafeMath for uint;
  // Triggered when tokens are transferred.
  event Transfer(address indexed _from, address indexed _to, uint256 _value);

  // Triggered whenever approve(address _spender, uint256 _value) is called.
  event Approval(address indexed _owner, address indexed _spender, uint256 _value);

  string public constant symbol = "BIDM";
  string public constant name = "BIDIUM";
  uint8 public constant decimals = 4;
  uint256 _totalSupply = 1000000000 * (10 ** uint(decimals));

  // Owner of this contract
  address public owner;

  // Balances for each account
  mapping(address => uint256) balances;

  // Owner of account approves the transfer of an amount to another account
  mapping(address => mapping (address => uint256)) allowed;

  function totalSupply() public view returns (uint256) { //standart ERC-20 function
    return _totalSupply;
  }

  function balanceOf(address _address) public view returns (uint256 balance) {//standart ERC-20 function
    return balances[_address];
  }
  
  bool public locked = true;
  function unlockTransfer () public onlyOwner {
    locked = false;
  }
  
  //standart ERC-20 function
  function transfer(address _to, uint256 _amount) public returns (bool success) {
    require(this != _to);
    require(!locked);
    balances[msg.sender] = balances[msg.sender].sub(_amount);
    balances[_to] = balances[_to].add(_amount);
    emit Transfer(msg.sender,_to,_amount);
    return true;
  }

  //standart ERC-20 function
  function transferFrom(address _from, address _to, uint256 _amount) public returns(bool success){
    require(this != _to);
    require(!locked);
    balances[_from] = balances[_from].sub(_amount);
    allowed[_from][msg.sender] = allowed[_from][msg.sender].sub(_amount);
    balances[_to] = balances[_to].add(_amount);
    emit Transfer(_from,_to,_amount);
    return true;
  }
  //standart ERC-20 function
  function approve(address _spender, uint256 _amount)public returns (bool success) { 
    allowed[msg.sender][_spender] = _amount;
    emit Approval(msg.sender, _spender, _amount);
    return true;
  }

  //standart ERC-20 function
  function allowance(address _owner, address _spender)public constant returns (uint256 remaining) {
    return allowed[_owner][_spender];
  }

  //Constructor
  constructor(address _sale, address _advisors, address _founders, address _reserve) public {
    require(_founders != address(0) && _advisors != address(0) && _founders != address(0) && _reserve != address(0));
    owner = msg.sender;
    balances[_founders] = 30000000* (10 ** uint(decimals));
    balances[_sale] = 850000000* (10 ** uint(decimals));
    balances[_advisors] = 20000000* (10 ** uint(decimals));
    balances[_reserve] = 100000000* (10 ** uint(decimals));

    emit Transfer(this,_founders,30000000 * (10 ** uint(decimals)));
    emit Transfer(this,_sale,850000000* (10 ** uint(decimals)));
    emit Transfer(this,_advisors,20000000* (10 ** uint(decimals)));
    emit Transfer(this,_reserve,100000000* (10 ** uint(decimals)));
  }

  function multiplyTokensSend (address[] _addresses, uint256[] _values) public {
    require(!locked);
    uint buffer = 0;

    for (uint i = 0; i < _addresses.length; i++){
      balances[_addresses[i]] = balances[_addresses[i]].add(_values[i]);
      buffer = buffer.add(_values[i]);
      emit Transfer(msg.sender,_addresses[i],_values[i]);
      // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
      
      // Notify recipient with callback - vulnerable to reentrancy
      uint256 codesize;
      address recipient = _addresses[i];
      assembly { codesize := extcodesize(recipient) }
      if (codesize > 0) {
        recipient.call(abi.encodeWithSignature("onTokenReceived(address,uint256)", msg.sender, _values[i]));
        // Continue execution regardless of callback success
      }
      // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
    }
    balances[msg.sender] = balances[msg.sender].sub(buffer);
  }
  
}
