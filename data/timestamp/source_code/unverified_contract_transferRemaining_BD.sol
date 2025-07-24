/*
 * ===== SmartInject Injection Details =====
 * Function      : transferRemaining
 * Vulnerability : Timestamp Dependence
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
 * Introduced a stateful, multi-transaction Timestamp Dependence vulnerability by implementing time-based transfer windows and cooling periods. The vulnerability requires multiple function calls to exploit because:
 * 
 * 1. **State Persistence**: Added state variables (lastTransferAttempt, transferWindowStart, transferredInWindow) that persist between transactions and accumulate effects over time
 * 
 * 2. **Multi-Transaction Exploitation**: 
 *    - Attackers need to make multiple calls to drain the contract balance since each call is limited by maxTransferPerWindow
 *    - The vulnerability requires building up state over multiple transactions to bypass the intended 60-day waiting period
 *    - Each transaction updates timestamps that affect subsequent transactions
 * 
 * 3. **Timestamp Manipulation Vectors**:
 *    - Miners can manipulate block.timestamp to reset transfer windows artificially
 *    - The currentWindow calculation (now / 86400) can be gamed by timestamp manipulation
 *    - Cooling period logic (now >= lastTransferAttempt + 3600) relies on potentially manipulable block.timestamp
 * 
 * 4. **Exploitation Sequence**:
 *    - Transaction 1: Call transferRemaining() to establish initial timestamps and transfer partial amount
 *    - Transaction 2+: Miners manipulate block.timestamp to either reset windows or bypass cooling periods
 *    - Multiple transactions needed to fully drain contract while circumventing time-based protections
 * 
 * 5. **Realistic Vulnerability Pattern**: The code appears to implement legitimate rate limiting and transfer windows but creates exploitable timestamp dependencies that require sequential transactions to abuse effectively.
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

  function Presale() {
    minGoal = 83.33 ether;
    startTime = 1505248886;
    endTime = 1506841199;   // Sept 30, 2017 midnight PT
    projectWallet = address(0x2a00BFd8379786ADfEbb6f2F59011535a4f8d4E4);
  }

  function transferToProjectWallet() {
    // only allow transfers if there is balance
    require(this.balance > 0);
    // only allow transfers if minimum goal is met
    require(totalRaised >= minGoal);
    if(!projectWallet.send(this.balance)) {
      revert();
    }
  }

  function refund() {
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

  // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
// Add state variables for timestamp-dependent transfer logic
uint256 private lastTransferAttempt;
uint256 private transferWindowStart;
uint256 private maxTransferPerWindow = 10 ether;
uint256 private transferredInWindow;

// ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
function transferRemaining() {
    // only allow transfer if presale has failed
    require(totalRaised < minGoal);
    // only allow transfer after refund window has passed
    require(now >= (endTime + 60 days));
    // only allow transfer if there is remaining balance
    require(this.balance > 0);
    // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
    
    // Vulnerable timestamp dependence: create transfer windows based on block.timestamp
    // Each 24-hour window allows limited transfers, but window calculation is manipulable
    uint256 currentWindow = now / 86400; // 24 hours in seconds
    uint256 storedWindow = transferWindowStart / 86400;
    
    // If we're in a new window, reset the transfer tracking
    if (currentWindow > storedWindow) {
        transferWindowStart = now;
        transferredInWindow = 0;
    }
    
    // Calculate transfer amount based on timestamp-dependent logic
    uint256 transferAmount;
    
    // Vulnerable: Different transfer limits based on time within block
    // Miners can manipulate block.timestamp to influence this calculation
    if (lastTransferAttempt == 0 || now >= lastTransferAttempt + 3600) {
        // First transfer or after 1 hour cooling period
        transferAmount = this.balance > maxTransferPerWindow ? maxTransferPerWindow : this.balance;
    } else {
        // Within cooling period - only allow smaller amounts
        uint256 remainingInWindow = maxTransferPerWindow - transferredInWindow;
        transferAmount = this.balance > remainingInWindow ? remainingInWindow : this.balance;
    }
    
    // Additional vulnerable check: use block.timestamp for access control
    require(transferAmount > 0);
    require(transferredInWindow + transferAmount <= maxTransferPerWindow);
    
    // Update state variables - these persist between transactions
    lastTransferAttempt = now;
    transferredInWindow += transferAmount;
    
    // Perform the transfer
    projectWallet.transfer(transferAmount);
}
    // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====

  function () payable {
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