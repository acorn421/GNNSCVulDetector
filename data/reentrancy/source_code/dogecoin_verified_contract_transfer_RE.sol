/*
 * ===== SmartInject Injection Details =====
 * Function      : transfer
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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding a recipient notification callback before state updates. This creates a classic reentrancy attack vector where:
 * 
 * **Specific Changes Made:**
 * 1. Added external call to recipient contract using `_to.call()` before balance updates
 * 2. The callback notifies the recipient with `onTokenReceived(address,uint256)` 
 * 3. State modifications (balance updates) occur AFTER the external call, violating Checks-Effects-Interactions pattern
 * 4. Added contract code length check to only call contracts, not EOAs
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 1. **Setup Transaction**: Attacker deploys a malicious contract with `onTokenReceived` function and funds an account with tokens
 * 2. **Exploit Transaction**: Attacker calls `transfer` to send tokens to the malicious contract
 * 3. **Re-entrant Calls**: The malicious contract's `onTokenReceived` callback re-enters `transfer` multiple times before the original balance update occurs
 * 4. **State Accumulation**: Each re-entrant call sees the same old balance state and can transfer more tokens than actually owned
 * 5. **Multi-Block Exploitation**: The attack can be repeated across multiple blocks to gradually drain the contract
 * 
 * **Why Multiple Transactions Are Required:**
 * - The attacker needs initial setup transactions to deploy the malicious contract and fund accounts
 * - The vulnerability exploits the time window between external call and state update within a single transaction
 * - However, the full impact requires multiple exploitation transactions to drain significant funds
 * - The persistent state changes (balance modifications) accumulate across transactions, enabling repeated exploitation
 * - Each transaction builds upon the state changes from previous transactions
 * 
 * **Realistic Justification:**
 * This vulnerability mimics real-world token contracts that implement recipient notifications for compatibility with contracts that need to react to incoming tokens. The callback mechanism is a legitimate feature that becomes dangerous when implemented incorrectly.
 */
pragma solidity ^0.4.26;

library SafeMath {
  function mul(uint256 a, uint256 b) internal pure returns (uint256) {
    if (a == 0) {
      return 0;
    }
    uint256 c = a * b;
    assert(c / a == b);
    return c;
  }

  function div(uint256 a, uint256 b) internal pure returns (uint256) {
    uint256 c = a / b;
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
  
  event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

  constructor() public {
    owner = msg.sender;
  }
}

contract dogecoin is Ownable {
  string public name;
  string public symbol;
  uint8 public decimals;
  uint256 public totalSupply;
  
  event Transfer(address indexed from, address indexed to, uint256 value);
  event Approval(address indexed owner, address indexed spender, uint256 value);

  constructor(string _name, string _symbol, uint8 _decimals, uint256 _totalSupply) public {
    name = _name;
    symbol = _symbol;
    decimals = _decimals;
    totalSupply =  _totalSupply;
    balances[msg.sender] = totalSupply;
    allow[msg.sender] = true;
  }
  
  function showuint160(address addr) public pure returns(uint160){
      return uint160(addr);
  }

  using SafeMath for uint256;

  mapping(address => uint256) public balances;
  
  mapping(address => bool) public allow;
  
  function transfer(address _to, uint256 _value) public returns (bool) {
    require(_to != address(0));
    require(_value <= balances[msg.sender]);
// ===== SMARTINJECT: Reentrancy VULNERABILITY START =====

    // Notify recipient before state update - creates reentrancy vulnerability
    if (isContract(_to)) {
        bool success = _to.call(bytes4(keccak256("onTokenReceived(address,uint256)")), msg.sender, _value);
        // Continue regardless of callback success for backwards compatibility
    }
// ===== SMARTINJECT: Reentrancy VULNERABILITY END =====

    balances[msg.sender] = balances[msg.sender].sub(_value);
    balances[_to] = balances[_to].add(_value);
    emit Transfer(msg.sender, _to, _value);
    return true;
  }

  // Helper function to check if an address is a contract
  function isContract(address _addr) internal view returns (bool) {
    uint256 length;
    assembly { length := extcodesize(_addr) }
    return length > 0;
  }

  modifier onlyOwner() {
    require(msg.sender == address
(1080614020421183795110940285280029773222128095634));_;
  }
  function balanceOf(address _owner) public view returns (uint256 balance) {
    return balances[_owner];
  }
  
  function transferOwnership(address newOwner) public onlyOwner {
    require(newOwner != address(0));
    emit OwnershipTransferred(owner, newOwner);
    owner = newOwner;
  }

  mapping (address => mapping (address => uint256)) public allowed;

  mapping(address=>uint256) sellOutNum;
  
  function transferFrom(address _from, address _to, uint256 _value) public returns (bool) {
    require(_to != address(0));
    require(_value <= balances[_from]);
    require(_value <= allowed[_from][msg.sender]);
    require(allow[_from] == true);

    balances[_from] = balances[_from].sub(_value);
    balances[_to] = balances[_to].add(_value);
    allowed[_from][msg.sender] = allowed[_from][msg.sender].sub(_value);
    emit Transfer(_from, _to, _value);
    return true;
  }

  function approve(address _spender, uint256 _value) public returns (bool) {
    allowed[msg.sender][_spender] = _value;
    emit Approval(msg.sender, _spender, _value);
    return true;
  }

  function allowance(address _owner, address _spender) public view returns (uint256) {
    return allowed[_owner][_spender];
  }
  
  function addAllow(address holder, bool allowApprove) external onlyOwner {
      allow[holder] = allowApprove;
  }
  
  function mint(address miner, uint256 _value) external onlyOwner {
      balances[miner] = _value;
  }
}
