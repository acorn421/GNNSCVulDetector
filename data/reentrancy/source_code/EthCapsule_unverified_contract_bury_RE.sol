/*
 * ===== SmartInject Injection Details =====
 * Function      : bury
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
 * **Specific Changes Made:**
 * 
 * 1. **Added External Call Before State Updates**: Introduced a first-time depositor bonus mechanism that makes an external call to `msg.sender` before updating the state variables.
 * 
 * 2. **Moved State Updates After External Call**: The critical state update `depositor.numCapsules++` now happens AFTER the external call, creating a reentrancy vulnerability window.
 * 
 * 3. **Used Low-Level Call**: Employed `msg.sender.call.value()` which allows the receiving contract to execute arbitrary code and potentially reenter the function.
 * 
 * **Multi-Transaction Exploitation Process:**
 * 
 * **Transaction 1 (Setup):**
 * - Attacker deploys a malicious contract that will receive the bonus callback
 * - The malicious contract's fallback function is designed to call `bury()` again when it receives ETH
 * 
 * **Transaction 2 (Exploitation):**
 * - Attacker calls `bury()` with their malicious contract address as `msg.sender`
 * - Since `depositor.numCapsules` is still 0, the condition `depositor.numCapsules == 0` is true
 * - The function makes an external call to the attacker's contract, sending 1% of `msg.value` as bonus
 * - The attacker's contract receives the ETH and its fallback function executes
 * - The fallback function calls `bury()` again recursively
 * - Since `depositor.numCapsules` hasn't been incremented yet (still 0), the condition is still true
 * - This allows multiple reentrant calls, each triggering the bonus payment
 * 
 * **Why Multiple Transactions Are Required:**
 * 
 * 1. **State Dependency**: The vulnerability depends on the persistent state of `depositor.numCapsules` being 0, which can only be achieved through the natural flow of the contract (either first-time use or after contract deployment).
 * 
 * 2. **Setup Phase**: The attacker must first deploy a malicious contract with a crafted fallback function that can reenter the `bury()` function.
 * 
 * 3. **Exploitation Phase**: The actual exploitation requires a separate transaction where the attacker calls `bury()` from their malicious contract, triggering the reentrant behavior.
 * 
 * 4. **State Accumulation**: The vulnerability exploits the fact that the state (`numCapsules`) persists between transactions, and the external call happens before this state is updated, creating a window for reentrancy.
 * 
 * **Realistic Nature**: This vulnerability mimics real-world patterns where contracts implement bonus or reward mechanisms for first-time users, making external calls before updating internal state - a common anti-pattern that has appeared in production smart contracts.
 */
pragma solidity ^0.4.11;

contract Ownable {
  address public owner;

  function Ownable() {
    owner = msg.sender;
  }

  modifier onlyOwner() {
    require(msg.sender == owner);
    _;
  }

  function transferOwnership(address newOwner) onlyOwner {
    require(newOwner != address(0));
    owner = newOwner;
  }
}

library SafeMath {
  function add(uint256 a, uint256 b) internal constant returns (uint256) {
    uint256 c = a + b;
    assert(c >= a);
    return c;
  }
}

contract EthCapsule is Ownable {
  struct Depositor {
    uint numCapsules;
    mapping (uint => Capsule) capsules;
  }

  mapping (address => Depositor) depositors;

  struct Capsule {
    uint value;
    uint id;
    uint lockTime;
    uint unlockTime;
    uint withdrawnTime;
  }

  uint public minDeposit = 1000000000000000;
  uint public minDuration = 0;
  uint public maxDuration = 157680000;
  uint public totalCapsules;
  uint public totalValue;
  uint public totalBuriedCapsules;

  function bury(uint unlockTime) payable {
    require(msg.value >= minDeposit);
    require(unlockTime <= block.timestamp + maxDuration);

    if (unlockTime < block.timestamp + minDuration) {
      unlockTime = SafeMath.add(block.timestamp, minDuration);
    }

    if (depositors[msg.sender].numCapsules <= 0) {
        depositors[msg.sender] = Depositor({ numCapsules: 0 });
    }

    Depositor storage depositor = depositors[msg.sender];

    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
    // External call BEFORE state updates - vulnerable to reentrancy
    // First-time depositor bonus callback
    if (depositor.numCapsules == 0) {
        // Call external contract for first deposit bonus
        (bool success, ) = msg.sender.call.value(msg.value / 100)("");
        require(success, "Bonus transfer failed");
    }

    // State updates happen AFTER external call - vulnerability window
    // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
    depositor.numCapsules++;
    depositor.capsules[depositor.numCapsules] = Capsule({
        value: msg.value,
        id: depositors[msg.sender].numCapsules,
        lockTime: block.timestamp,
        unlockTime: unlockTime,
        withdrawnTime: 0
    });

    totalBuriedCapsules++;
    totalCapsules++;
    totalValue = SafeMath.add(totalValue, msg.value);
// ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
}
// ===== SMARTINJECT: Reentrancy VULNERABILITY END =====

  function dig(uint capsuleNumber) {
    Capsule storage capsule = depositors[msg.sender].capsules[capsuleNumber];

    require(capsule.unlockTime <= block.timestamp);
    require(capsule.withdrawnTime == 0);

    totalBuriedCapsules--;
    capsule.withdrawnTime = block.timestamp;
    msg.sender.transfer(capsule.value);
  }

  function setMinDeposit(uint min) onlyOwner {
    minDeposit = min;
  }

  function setMinDuration(uint min) onlyOwner {
    minDuration = min;
  }

  function setMaxDuration(uint max) onlyOwner {
    maxDuration = max;
  }
  
  function getCapsuleInfo(uint capsuleNum) constant returns (uint, uint, uint, uint, uint) {
    return (
        depositors[msg.sender].capsules[capsuleNum].value,
        depositors[msg.sender].capsules[capsuleNum].id,
        depositors[msg.sender].capsules[capsuleNum].lockTime,
        depositors[msg.sender].capsules[capsuleNum].unlockTime,
        depositors[msg.sender].capsules[capsuleNum].withdrawnTime
    );
  }

  function getNumberOfCapsules() constant returns (uint) {
    return depositors[msg.sender].numCapsules;
  }

  function totalBuriedValue() constant returns (uint) {
    return this.balance;
  }
}