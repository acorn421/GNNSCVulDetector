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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding a `transferInProgress` mapping that tracks ongoing transfers. The vulnerability requires multiple transactions to exploit because:
 * 
 * 1. **Stateful Tracking**: Added `transferInProgress[msg.sender][target]` mapping that persists between transactions and tracks transfer amounts
 * 2. **State Accumulation**: The function accumulates pending transfer amounts across multiple calls
 * 3. **Delayed State Cleanup**: The `transferInProgress` state is only cleared at the end, after the external call
 * 4. **Multi-Transaction Exploitation Path**: 
 *    - Transaction 1: Malicious contract initiates transfer, sets up `transferInProgress` state
 *    - Transaction 2: During `tokenFallback`, the malicious contract can re-enter and see the accumulated state
 *    - Transaction 3+: Multiple re-entrancies can accumulate more state before cleanup
 *    - The attacker can exploit the fact that `transferInProgress` shows accumulated amounts from previous transactions
 * 
 * The vulnerability is exploitable because the external call to `tokenFallback` happens before the `transferInProgress` state is cleared, allowing reentrancy attacks that can observe and manipulate the accumulated state across multiple transactions. This creates a realistic multi-transaction attack vector where an attacker needs to build up state over multiple calls to fully exploit the vulnerability.
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
  // Added declaration for transferInProgress mapping
  mapping(address => mapping(address => uint256)) public transferInProgress;
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
    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
    // Start transfer process - allows monitoring of transfer state
    if (transferInProgress[msg.sender][target] == 0) {
        transferInProgress[msg.sender][target] = qty;
    } else {
        // Accumulate pending transfers for multi-transaction scenarios
        transferInProgress[msg.sender][target] = transferInProgress[msg.sender][target].add(qty);
    }
    
    // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
    balanceOf[msg.sender] = balanceOf[msg.sender].sub(qty);
    balanceOf[target] = balanceOf[target].add(qty);
    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
    
    if (isContract(target)) {
        // External call happens before clearing transfer tracking state
        TokenReceiver(target).tokenFallback(target, qty, data);
    }
    
    emit Transfer(msg.sender, target, qty);
    
    // Clear transfer tracking only after successful completion
    transferInProgress[msg.sender][target] = 0;
    
    // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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
    allowance[msg.sender][spender] = qty;
    emit Approval(msg.sender, spender, qty);
    return true;
  }
  function approveAndCall(address spender, uint256 qty, bytes data) external returns (bool) {
    require(approve(spender, qty));
    TokenReceiver(spender).receiveApproval(msg.sender, qty, this, data);
    return true;
  }
}
