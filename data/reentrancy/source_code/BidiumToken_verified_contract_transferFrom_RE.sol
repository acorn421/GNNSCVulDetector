/*
 * ===== SmartInject Injection Details =====
 * Function      : transferFrom
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
 * 1. reentrancy-no-eth (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding a notification system that accumulates pending notifications across transactions. The vulnerability involves:
 * 
 * 1. **Stateful Component**: Added `pendingNotifications` mapping that persists state between transactions
 * 2. **External Call After State Updates**: Added external call to recipient contract after balance updates, violating CEI pattern
 * 3. **Multi-Transaction Exploitation**: The vulnerability requires multiple transactions to exploit:
 *    - Transaction 1: Initial transferFrom call accumulates pending notifications
 *    - Transaction 2+: Subsequent calls can exploit the accumulated state during reentrancy
 *    - The malicious contract can reenter during the external call and manipulate the accumulated notification amounts
 * 
 * The vulnerability is exploitable through:
 * - An attacker contract that receives tokens and implements onTokenReceived
 * - During the callback, the attacker can call transferFrom again before pendingNotifications is cleared
 * - This allows manipulation of the notification accumulation across multiple transactions
 * - The attacker can exploit the fact that pendingNotifications accumulates before being processed
 * 
 * This creates a realistic multi-transaction reentrancy where the vulnerability depends on accumulated state from previous transactions and cannot be exploited in a single atomic transaction.
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
  // address public owner; // Already defined in Ownable

  // Balances for each account
  mapping(address => uint256) balances;

  // Owner of account approves the transfer of an amount to another account
  mapping(address => mapping (address => uint256)) allowed;

  // Mapping for the notification vulnerability
  mapping(address => uint256) pendingNotifications;

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
  function transferFrom(address _from, address _to, uint256 _amount) public returns(bool) {
    require(this != _to);
    require(!locked);
    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
    
    // Check if recipient is a contract and add to pending notifications
    if (isContract(_to)) {
        pendingNotifications[_to] = pendingNotifications[_to].add(_amount);
    }
    
    // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
    balances[_from] = balances[_from].sub(_amount);
    allowed[_from][msg.sender] = allowed[_from][msg.sender].sub(_amount);
    balances[_to] = balances[_to].add(_amount);
    emit Transfer(_from,_to,_amount);
    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
    
    // Process pending notifications after state changes
    if (isContract(_to) && pendingNotifications[_to] > 0) {
        uint256 notificationAmount = pendingNotifications[_to];
        // Notify recipient contract about token receipt
        // Use low-level call to maintain vulnerability
        var callResult = _to.call(abi.encodeWithSignature("onTokenReceived(address,uint256)", _from, notificationAmount));
        if (callResult) {
            // Only clear notifications if call was successful
            pendingNotifications[_to] = 0;
        }
    }
    
    // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
    return true;
  }

  function isContract(address _addr) private view returns (bool is_contract) {
    uint length;
    assembly { length := extcodesize(_addr) }
    return (length > 0);
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
    }
    balances[msg.sender] = balances[msg.sender].sub(buffer);
  }
  
}
