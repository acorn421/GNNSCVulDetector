/*
 * ===== SmartInject Injection Details =====
 * Function      : approve
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 1 findings
 * Total Found   : 2 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the spender contract through receiveApproval() callback. The vulnerability exploits the fact that:
 * 
 * 1. **State Modification Before Complete Transaction**: The allowance is set before the external call, but the transaction isn't complete
 * 2. **External Call to User-Controlled Contract**: The spender can be a malicious contract that implements receiveApproval()
 * 3. **Multi-Transaction Exploitation Pattern**: 
 *    - Transaction 1: User calls approve() for a malicious contract
 *    - The malicious contract's receiveApproval() can call back into the token contract
 *    - It can call transferFrom() using the just-approved allowance
 *    - It can also call approve() again to modify allowances for other addresses
 *    - Transaction 2+: Additional calls can exploit the manipulated state
 * 
 * **Multi-Transaction Requirements**:
 * - The vulnerability requires the initial approve() call to trigger the reentrancy
 * - The malicious contract must be deployed and have receiveApproval() implemented (separate transaction)
 * - The exploit involves multiple state manipulations across the reentrant calls
 * - The attacker can drain tokens by repeatedly calling transferFrom() or manipulating allowances for accomplices
 * 
 * **State Persistence**: The allowance mappings persist between transactions, and the malicious contract can exploit this persistent state through reentrant calls that modify allowances or transfer tokens before the original approve() transaction completes.
 * 
 * This creates a realistic vulnerability where a malicious spender contract can exploit the approval notification to manipulate token allowances and transfers in ways the original approver never intended.
 */
pragma solidity ^0.4.24;

interface TokenReceiver {
  function tokenFallback(address from, uint256 qty, bytes data) external;
  function receiveApproval(address from, uint256 tokens, address token, bytes data) external;
}

library SafeMath {
  function sub(uint256 a, uint256 b) internal pure returns (uint256) {
    require(b <= a);
    return a - b;
  }
  function add(uint256 a, uint256 b) internal pure returns (uint256) {
    uint256 c = a + b;
    require(c >= a);
    return c;
  }
}

contract ARIYAX {
  using SafeMath for uint256;
  mapping (address => uint256) public balanceOf;
  mapping (address => mapping (address => uint256)) public allowance;
  uint256 public decimals = 18;
  string public name = "ARIYAX";
  string public symbol = "ARYX";
  uint256 public totalSupply = 1000000000e18;
  event Transfer(address indexed from, address indexed to, uint256 qty);
  event Approval(address indexed from, address indexed spender, uint256 qty);
  constructor() public {
    balanceOf[msg.sender] = totalSupply;
  }
  function isContract(address target) internal view returns (bool) {
    uint256 codeLength;
    assembly {
      codeLength := extcodesize(target)
    }
    return codeLength > 0;
  }
  function transfer(address target, uint256 qty, bytes data) public returns (bool) {
    balanceOf[msg.sender] = balanceOf[msg.sender].sub(qty);
    balanceOf[target] = balanceOf[target].add(qty);
    if (isContract(target)) {
      TokenReceiver(target).tokenFallback(target, qty, data);
    }
    emit Transfer(msg.sender, target, qty);
    return true;
  }
  function transfer(address target, uint256 qty) external returns (bool) {
    return transfer(target, qty, "");
  }
  function transferFrom(address from, address to, uint256 qty) external returns (bool) {
    allowance[from][msg.sender] = allowance[from][msg.sender].sub(qty);
    balanceOf[from] = balanceOf[from].sub(qty);
    balanceOf[to] = balanceOf[to].add(qty);
    emit Transfer(from, to, qty);
    return true;
  }
  function approve(address spender, uint256 qty) public returns (bool) {
    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
    // Update allowance first
    allowance[msg.sender][spender] = qty;
    
    // Notify spender contract if it's a contract address
    if (isContract(spender)) {
        TokenReceiver(spender).receiveApproval(msg.sender, qty, this, "");
    }
    
    // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
    emit Approval(msg.sender, spender, qty);
    return true;
  }
  function approveAndCall(address spender, uint256 qty, bytes data) external returns (bool) {
    require(approve(spender, qty));
    TokenReceiver(spender).receiveApproval(msg.sender, qty, this, data);
    return true;
  }
}