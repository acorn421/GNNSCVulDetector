/*
 * ===== SmartInject Injection Details =====
 * Function      : receiveApproval
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
 * This modification introduces a stateful, multi-transaction reentrancy vulnerability by implementing a two-stage approval process:
 * 
 * **Specific Changes Made:**
 * 1. **Added State Variables**: Introduced three mappings to track approval states across transactions:
 *    - `pendingApprovals`: Stores approval amounts waiting for processing
 *    - `processingApproval`: Tracks which approvals are in progress
 *    - `approvalCallback`: Stores callback contract addresses
 * 
 * 2. **Two-Stage Processing Logic**: 
 *    - Stage 1: Sets up pending state and requires a second transaction
 *    - Stage 2: Completes processing but makes external calls before clearing state
 * 
 * 3. **External Calls Before State Updates**: Added vulnerable external calls that occur before critical state variables are cleared
 * 
 * **Multi-Transaction Exploitation Path:**
 * 1. **Transaction 1**: Attacker calls `receiveApproval()` to initialize pending state
 * 2. **Transaction 2**: Attacker calls `receiveApproval()` again to trigger Stage 2 processing
 * 3. **During Stage 2**: The external callback allows the attacker to re-enter and manipulate the still-active state
 * 
 * **Why Multi-Transaction is Required:**
 * - The vulnerability requires the `processingApproval` state to be set to `true` in a previous transaction
 * - The external callback in Stage 2 can only exploit the vulnerability when `pendingApprovals` still contains a non-zero value
 * - Single-transaction exploitation is impossible because Stage 1 exits early before any external calls
 * - The state accumulation from Transaction 1 enables the reentrancy exploitation in Transaction 2
 * 
 * **Exploitation Scenario:**
 * 1. Attacker deploys a malicious callback contract
 * 2. Calls `receiveApproval()` with callback address in data parameter (Transaction 1)
 * 3. Calls `receiveApproval()` again (Transaction 2)
 * 4. During the callback in Stage 2, the malicious contract re-enters `receiveApproval()`
 * 5. Since `processingApproval[from][token]` is still `true` and `pendingApprovals[from][token]` is non-zero, the attacker can manipulate the approval process multiple times before state is cleared
 */
pragma solidity ^0.4.24;

interface TokenReceiver {
  function tokenFallback(address from, uint256 qty, bytes data) external;
}

// ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
contract ApprovalProcessor {
    // Added state variables to track approval processing
    mapping(address => mapping(address => uint256)) public pendingApprovals;
    mapping(address => mapping(address => bool)) public processingApproval;
    mapping(address => address) public approvalCallback;
    // Declare the missing event
    event ApprovalProcessed(address indexed from, address indexed token, uint256 approvedAmount);

    function receiveApproval(address from, uint256 tokens, address token, bytes data) external {
        // Parse callback address from data if provided
        address callbackContract;
        if (data.length >= 20) {
            assembly {
                callbackContract := mload(add(data, 20))
            }
        }
        // Stage 1: Initial approval processing - set up pending state
        if (!processingApproval[from][token]) {
            pendingApprovals[from][token] = tokens;
            processingApproval[from][token] = true;
            // Store callback for later use
            if (callbackContract != address(0)) {
                approvalCallback[from] = callbackContract;
            }
            // External call to token contract for validation - VULNERABLE: Before final state update
            if (token != address(0)) {
                // This external call can trigger reentrancy
                bool success = token.call(abi.encodeWithSignature("balanceOf(address)", from));
                require(success, "Token validation failed");
            }
            return; // Exit early, requires second call to complete
        }
        // Stage 2: Final approval processing - only if already in processing state
        if (processingApproval[from][token] && pendingApprovals[from][token] > 0) {
            uint256 approvedAmount = pendingApprovals[from][token];
            // External callback BEFORE clearing critical state - VULNERABLE
            if (approvalCallback[from] != address(0)) {
                // This external call can re-enter and manipulate state
                approvalCallback[from].call(abi.encodeWithSignature("onApprovalReceived(address,uint256,address)", from, approvedAmount, token));
            }
            // State clearing happens AFTER external call - VULNERABLE
            processingApproval[from][token] = false;
            pendingApprovals[from][token] = 0;
            delete approvalCallback[from];
            // Emit event for successful processing
            emit ApprovalProcessed(from, token, approvedAmount);
        }
    }
}
// ===== SMARTINJECT: Reentrancy VULNERABILITY END =====

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
    allowance[msg.sender][spender] = qty;
    emit Approval(msg.sender, spender, qty);
    return true;
  }
  function approveAndCall(address spender, uint256 qty, bytes data) external returns (bool) {
    require(approve(spender, qty));
    ApprovalProcessor(spender).receiveApproval(msg.sender, qty, this, data);
    return true;
  }
}
