/*
 * ===== SmartInject Injection Details =====
 * Function      : transferToProjectWallet
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 4 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Injected a stateful, multi-transaction timestamp dependence vulnerability by adding time-based access controls using block.timestamp. The vulnerability requires multiple transactions to exploit:
 * 
 * 1. **Multi-Transaction Requirement**: The first call initializes the transfer window (transferWindowStart) and returns without transferring funds. Subsequent calls must wait for cooldown periods and can only execute during 1-hour windows every 6 hours.
 * 
 * 2. **State Persistence**: The contract stores transferWindowStart and lastTransferAttempt in state variables that persist between transactions, creating stateful behavior.
 * 
 * 3. **Timestamp Manipulation Vector**: Miners can manipulate block.timestamp (within ~900 second drift tolerance) to:
 *    - Control when the transfer window opens after initialization
 *    - Bypass cooldown periods by manipulating timestamps
 *    - Force transfers to occur during favorable time windows
 *    - Prevent legitimate transfers by mining blocks with timestamps outside the window
 * 
 * 4. **Exploitation Scenario**: An attacker (miner) can:
 *    - Transaction 1: Call function to initialize transfer window at a strategic timestamp
 *    - Transaction 2+: Wait for cooldown period, then manipulate block timestamps to ensure transfers occur when beneficial (e.g., during low gas prices, before token price drops, etc.)
 * 
 * The vulnerability is realistic as it implements "security" features (cooldown periods and transfer windows) commonly seen in DeFi protocols, but relies on unreliable block.timestamp for critical timing logic.
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

  // Added variable declarations necessary for transferToProjectWallet
  uint256 public transferWindowStart;
  uint256 public lastTransferAttempt;
  uint256 public transferCooldownPeriod = 1 hours; // example value

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
    // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
    
    // Initialize transfer window if not set
    if (transferWindowStart == 0) {
        transferWindowStart = block.timestamp;
        lastTransferAttempt = block.timestamp;
        return; // First call just initializes the window
    }
    
    // Enforce minimum cooling period between transfer attempts
    require(block.timestamp >= lastTransferAttempt + transferCooldownPeriod);
    
    // Only allow transfers during specific time windows to prevent manipulation
    // Transfer window is open for 1 hour every 6 hours after initialization
    uint256 timeSinceWindowStart = (block.timestamp - transferWindowStart) % (6 * 1 hours);
    require(timeSinceWindowStart < 1 hours);
    
    // Store timestamp for cooldown enforcement
    lastTransferAttempt = block.timestamp;
    
    // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
    if(!projectWallet.send(this.balance)) {
      revert();
    }
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
