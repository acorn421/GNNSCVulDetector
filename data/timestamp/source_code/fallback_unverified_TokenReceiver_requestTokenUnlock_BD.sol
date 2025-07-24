/*
 * ===== SmartInject Injection Details =====
 * Function      : requestTokenUnlock
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 2 issues
 * Retry Count   : 0
 *
 * === Description ===
 * This vulnerability introduces a timestamp dependence issue where the unlock mechanism relies on 'now' (block.timestamp) for timing validation. An attacker can manipulate the timing by controlling block timestamps within the allowed range (up to 15 minutes in the future). The vulnerability is stateful and multi-transaction: first call requestTokenUnlock() to set the unlock request time, then wait for the delay period, then call executeTokenUnlock(). A malicious miner could manipulate timestamps to either prevent legitimate unlocks or allow premature unlocks.
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

  // === FALLBACK INJECTION: Timestamp Dependence ===
  // Moved these state variable declarations outside constructor to fix compilation error
  mapping (address => uint256) public unlockRequestTime;
  mapping (address => uint256) public pendingUnlockAmount;
  uint256 public unlockDelay = 1 days;
  // === END FALLBACK INJECTION ===

  constructor() public {
    balanceOf[msg.sender] = totalSupply;
    // === FALLBACK INJECTION: Timestamp Dependence ===
    // Variable declarations were moved out of the constructor for correct Solidity syntax
    // === END FALLBACK INJECTION ===
  }
  
  // === FALLBACK INJECTION: Timestamp Dependence ===
  function requestTokenUnlock(uint256 qty) external returns (bool) {
    require(balanceOf[msg.sender] >= qty, "Insufficient balance");
    unlockRequestTime[msg.sender] = now;
    pendingUnlockAmount[msg.sender] = qty;
    return true;
  }
  
  function executeTokenUnlock() external returns (bool) {
    require(pendingUnlockAmount[msg.sender] > 0, "No pending unlock");
    require(now >= unlockRequestTime[msg.sender] + unlockDelay, "Unlock delay not met");
    
    uint256 amount = pendingUnlockAmount[msg.sender];
    pendingUnlockAmount[msg.sender] = 0;
    unlockRequestTime[msg.sender] = 0;
    
    // Transfer tokens to a special unlock address or burn them
    balanceOf[msg.sender] = balanceOf[msg.sender].sub(amount);
    emit Transfer(msg.sender, address(0), amount);
    
    return true;
  }
  // === END FALLBACK INJECTION ===

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
