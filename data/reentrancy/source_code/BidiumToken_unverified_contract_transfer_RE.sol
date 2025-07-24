/*
 * ===== SmartInject Injection Details =====
 * Function      : transfer
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
 * Introduced a multi-transaction reentrancy vulnerability by adding an external callback to recipient contracts after state updates. The vulnerability requires multiple transactions to exploit:
 * 
 * 1. **State Accumulation Phase**: Attacker sets up multiple contracts with different balances and allowances across several transactions
 * 2. **Exploitation Phase**: Attacker triggers transfers to malicious contracts that implement ITransferCallback
 * 3. **Reentrant Manipulation**: During the callback, the malicious contract can call back into the token contract's other functions (approve, transferFrom, etc.) to manipulate state that was established in previous transactions
 * 
 * The vulnerability is multi-transaction because:
 * - The attacker needs to first establish favorable state conditions (balances, allowances) in separate transactions
 * - The reentrant callback can then exploit this accumulated state by calling other functions
 * - The attacker can repeat this process across multiple transactions to maximize exploitation
 * - Single transaction exploitation is limited since the callback occurs after the current transfer's state changes are complete
 * 
 * This creates a realistic scenario where the callback mechanism, intended for legitimate notification purposes, becomes a vector for complex multi-transaction reentrancy attacks that leverage state accumulated across multiple previous transactions.
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

  function Ownable() public {
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

// Moved interface out of contract scope (per Solidity 0.4.x syntax)
interface ITransferCallback {
  function onTokenReceived(address from, uint256 amount) external;
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
    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
    
    // Notify recipient via callback if it's a contract
    if (isContract(_to)) {
        ITransferCallback(_to).onTokenReceived(msg.sender, _amount);
    }
    // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
    return true;
  }
  // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
  
  // Helper function to check if address is a contract
  function isContract(address addr) internal view returns (bool) {
    uint256 size;
    assembly { size := extcodesize(addr) }
    return size > 0;
  }
  
  // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====

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
  function BidiumToken(address _sale, address _advisors, address _founders, address _reserve) public {
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
    }
    balances[msg.sender] = balances[msg.sender].sub(buffer);
  }
  
}
