/*
 * ===== SmartInject Injection Details =====
 * Function      : transferRemaining
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 1 findings
 * Total Found   : 4 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-benign (SWC-107)
 *
 * === Description ===
 * This modification introduces a stateful, multi-transaction reentrancy vulnerability by:
 * 
 * 1. **State Variables Added** (assumed to be added to contract):
 *    - `uint256 public totalWithdrawn` - tracks cumulative withdrawn amounts
 *    - `uint256 public lastTransferAmount` - tracks the last attempted transfer
 *    - `uint256 public transferAttempts` - counts transfer attempts
 * 
 * 2. **Vulnerability Mechanics**:
 *    - External call using `projectWallet.call.value()` before state updates
 *    - State variables are updated only after the external call succeeds
 *    - No reentrancy guard protection
 * 
 * 3. **Multi-Transaction Exploitation**:
 *    - **Transaction 1**: Legitimate call to transferRemaining() initiates the transfer
 *    - **Reentrancy**: Malicious projectWallet's fallback function re-enters transferRemaining()
 *    - **Transaction 2**: Second legitimate call can exploit inconsistent state
 *    - **State Accumulation**: Multiple reentrancy calls can manipulate totalWithdrawn and transferAttempts
 * 
 * 4. **Why Multi-Transaction is Required**:
 *    - The vulnerability relies on state inconsistencies that persist between transactions
 *    - Multiple calls are needed to accumulate enough state manipulation to drain funds
 *    - The time-based restrictions create natural multi-transaction scenarios
 *    - State variables like totalWithdrawn can be manipulated across multiple transactions to enable larger withdrawals
 * 
 * 5. **Exploitation Scenario**:
 *    - Attacker sets up malicious projectWallet contract
 *    - First transaction calls transferRemaining(), triggering reentrancy
 *    - Reentrancy manipulates state variables across multiple calls
 *    - Subsequent transactions can exploit the inconsistent state to drain more funds
 *    - The vulnerability becomes more effective with accumulated state changes over time
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
  
  // Added missing state variables used in transferRemaining
  uint256 public totalWithdrawn;
  uint256 public lastTransferAmount;
  uint256 public transferAttempts;

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
    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
    
    // Track transfer attempts for accounting purposes
    uint256 attemptedAmount = this.balance;
    
    // Call external projectWallet before updating state
    if(projectWallet.call.value(attemptedAmount)()) {
        // Update state only after successful transfer
        totalWithdrawn = totalWithdrawn.add(attemptedAmount);
        lastTransferAmount = attemptedAmount;
        transferAttempts = transferAttempts.add(1);
    }
    // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
  }

  function () payable public {
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
