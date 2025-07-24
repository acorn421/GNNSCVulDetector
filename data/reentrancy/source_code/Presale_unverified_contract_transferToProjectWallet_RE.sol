/*
 * ===== SmartInject Injection Details =====
 * Function      : transferToProjectWallet
 * Vulnerability : Reentrancy
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 3 issues
 * Retry Count   : 0
 *
 * === Description ===
 * **STATEFUL, MULTI-TRANSACTION REENTRANCY VULNERABILITY**
 * 
 * **1. Specific Changes Made:**
 * - Added `transferAttempts++` counter before external call
 * - Added state variables that would need to be declared in contract:
 *   - `mapping(address => bool) public transferInitiated`
 *   - `uint256 public lastTransferAmount`
 *   - `uint256 public lastTransferTime`
 *   - `mapping(address => bool) public suspiciousActivity`
 *   - `uint256 public transferAttempts`
 * - Added state updates AFTER the external call to projectWallet.send()
 * - Added conditional logic that depends on accumulated state (transferAttempts > 1)
 * 
 * **2. Multi-Transaction Exploitation Scenario:**
 * 
 * **Transaction 1 - State Manipulation:**
 * - Attacker calls transferToProjectWallet()
 * - During projectWallet.send(), attacker's malicious contract reenters
 * - In reentrancy, transferAttempts is incremented again
 * - State becomes inconsistent but persists after transaction ends
 * 
 * **Transaction 2 - Exploit Accumulated State:**
 * - Attacker calls transferToProjectWallet() again
 * - Function sees transferAttempts > 1 from previous transaction
 * - Triggers suspiciousActivity[msg.sender] = true
 * - Attacker can exploit this persistent state inconsistency
 * 
 * **Transaction 3 - Complete Attack:**
 * - Attacker uses the manipulated state from previous transactions
 * - Can bypass certain checks or manipulate contract logic
 * - The accumulated state changes enable the final exploit
 * 
 * **3. Why Multi-Transaction is Required:**
 * 
 * **State Persistence Between Calls:**
 * - transferAttempts counter persists between transactions
 * - transferInitiated mapping maintains state across calls
 * - suspiciousActivity flag is set based on accumulated attempts
 * 
 * **Exploitation Requires Sequence:**
 * - Single transaction cannot manipulate transferAttempts meaningfully
 * - The vulnerability relies on state built up over multiple calls
 * - Reentrancy in transaction 1 sets up state for exploitation in transaction 2+
 * 
 * **Realistic Attack Vector:**
 * - Attacker needs to first establish the manipulated state
 * - Then exploit the inconsistent state in subsequent transactions
 * - The state variables provide legitimate-looking audit trail functionality
 * 
 * **4. Technical Vulnerability Details:**
 * - Violates Checks-Effects-Interactions pattern
 * - State updates after external call create reentrancy window
 * - Persistent state variables enable cross-transaction exploitation
 * - Counter manipulation allows attacker to influence contract behavior across multiple calls
 * 
 * This creates a realistic, stateful reentrancy vulnerability that requires multiple transactions to exploit effectively, making it much more subtle than traditional single-transaction reentrancy attacks.
 */
pragma solidity ^0.4.16;

/**
 * @title SafeMath
 * @dev Math operations with safety checks that throw on error
 */
library SafeMath {
  function mul(uint256 a, uint256 b) internal constant returns (uint256) {
    uint256 c = a * b;
    assert(a == 0 || c / a == b);
    return c;
  }

  function div(uint256 a, uint256 b) internal constant returns (uint256) {
    // assert(b > 0); // Solidity automatically throws when dividing by 0
    uint256 c = a / b;
    // assert(a == b * c + a % b); // There is no case in which this doesn't hold
    return c;
  }

  function sub(uint256 a, uint256 b) internal constant returns (uint256) {
    assert(b <= a);
    return a - b;
  }

  function add(uint256 a, uint256 b) internal constant returns (uint256) {
    uint256 c = a + b;
    assert(c >= a);
    return c;
  }
}

contract Presale {
  using SafeMath for uint256;

  mapping (address => uint256) public balances;

  // Minimum amount of wei required for presale to be successful.  If not successful, refunds are provided.
  uint256 public minGoal;
  // The epoch unix timestamp of when the presale starts
  uint256 public startTime;
  // The epoch unix timestamp of when the presale ends
  uint256 public endTime;
  // The wallet address that the funds will be sent to
  address public projectWallet;

  uint256 private totalRaised;

  // Declarations to fix compilation errors
  uint256 public transferAttempts; // Counter for transfer attempts
  mapping(address => bool) public transferInitiated; // Tracks if transfer was initiated by address
  uint256 public lastTransferAmount; // Stores last transfer amount
  uint256 public lastTransferTime; // Stores last transfer time
  mapping(address => bool) public suspiciousActivity; // Flags suspicious activity

  function Presale() public {
    minGoal = 83.33 ether;
    startTime = 1505248886;
    endTime = 1506841199;   // Sept 30, 2017 midnight PT
    projectWallet = address(0x2a00BFd8379786ADfEbb6f2F59011535a4f8d4E4);
  }

  function transferToProjectWallet() public {
    // only allow transfers if there is balance
    require(this.balance > 0);
    // only allow transfers if minimum goal is met
    require(totalRaised >= minGoal);
    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
    
    // Track transfer attempts for audit purposes
    transferAttempts++;
    
    // Store amount being transferred for logging
    uint256 transferAmount = this.balance;
    
    if(!projectWallet.send(transferAmount)) {
    // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
      revert();
    }
    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
    
    // Update state after external call - VULNERABLE TO REENTRANCY
    transferInitiated[msg.sender] = true;
    lastTransferAmount = transferAmount;
    lastTransferTime = now;
    
    // Additional state update that persists between transactions
    if (transferAttempts > 1) {
        // Mark as suspicious activity if multiple attempts
        suspiciousActivity[msg.sender] = true;
    }
    // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
  }

  function refund() public {
    // only allow refund if the presale has ended
    require(now > endTime);
    // only allow refund if the minGoal has not been reached
    require(totalRaised < minGoal);
    // only allow refund during a 60 day window after presale ends
    require(now < (endTime + 60 days));
    uint256 amount = balances[msg.sender];
    // only allow refund if investor has invested
    require(amount > 0);
    // after refunding, zero out balance
    balances[msg.sender] = 0;
    msg.sender.transfer(amount);
  }

  function transferRemaining() public {
    // only allow transfer if presale has failed
    require(totalRaised < minGoal);
    // only allow transfer after refund window has passed
    require(now >= (endTime + 60 days));
    // only allow transfer if there is remaining balance
    require(this.balance > 0);
    projectWallet.transfer(this.balance);
  }

  function () public payable {
    // only allow payments greater than 0
    require(msg.value > 0);
    // only allow payments after presale has started
    require(now >= startTime);
    // only allow payments before presale has ended
    require(now <= endTime);
    // if all checks pass, then add amount to balance of the sender
    balances[msg.sender] = balances[msg.sender].add(msg.value);
    totalRaised = totalRaised.add(msg.value);
  }
}
