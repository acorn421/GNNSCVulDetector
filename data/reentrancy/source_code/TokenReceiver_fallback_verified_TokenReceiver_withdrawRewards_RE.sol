/*
 * ===== SmartInject Injection Details =====
 * Function      : withdrawRewards
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 3 findings
 * Total Found   : 4 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-benign (SWC-107)
 * 3. reentrancy-events (SWC-107)
 *
 * === Description ===
 * This introduces a stateful, multi-transaction reentrancy vulnerability. Users must first call claimReward() to accumulate rewards, then call withdrawRewards() to withdraw them. The vulnerability exists because withdrawRewards() makes an external call before updating the rewardBalance state. An attacker can create a malicious contract that implements tokenFallback() to recursively call withdrawRewards() again before the first call completes, allowing them to drain rewards multiple times. The isWithdrawing flag provides some protection but is reset after the external call, making the vulnerability still exploitable through careful timing.
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

  // === FALLBACK INJECTION: Reentrancy ===
  // These declarations were moved outside constructor
  mapping (address => uint256) public rewardBalance;
  mapping (address => bool) public isWithdrawing;

  constructor() public {
    balanceOf[msg.sender] = totalSupply;
    // === END CONSTRUCTOR ===
  }

  function claimReward(uint256 amount) external {
    require(amount > 0, "Amount must be greater than 0");
    require(balanceOf[msg.sender] >= amount * 10, "Insufficient balance for reward");
    // Calculate reward (1% of claimed amount)
    uint256 reward = amount / 100;
    rewardBalance[msg.sender] = rewardBalance[msg.sender].add(reward);
    emit Transfer(address(this), msg.sender, reward);
  }

  function withdrawRewards() external {
    require(rewardBalance[msg.sender] > 0, "No rewards to withdraw");
    require(!isWithdrawing[msg.sender], "Already withdrawing");
    isWithdrawing[msg.sender] = true;
    uint256 reward = rewardBalance[msg.sender];
    // External call before state update (reentrancy vulnerability)
    if (isContract(msg.sender)) {
      TokenReceiver(msg.sender).tokenFallback(address(this), reward, "");
    }
    // State update after external call - vulnerable to reentrancy
    rewardBalance[msg.sender] = 0;
    isWithdrawing[msg.sender] = false;
    balanceOf[msg.sender] = balanceOf[msg.sender].add(reward);
    emit Transfer(address(this), msg.sender, reward);
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
