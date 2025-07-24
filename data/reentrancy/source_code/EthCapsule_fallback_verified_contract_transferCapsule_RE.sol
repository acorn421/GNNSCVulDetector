/*
 * ===== SmartInject Injection Details =====
 * Function      : transferCapsule
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 2 findings
 * Total Found   : 5 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-eth (SWC-107)
 * 2. reentrancy-benign (SWC-107)
 *
 * === Description ===
 * This function introduces a stateful reentrancy vulnerability that requires multiple transactions to exploit. The vulnerability occurs because state changes happen after the external call to recipient.call.value(). An attacker can create a malicious contract that, when called, re-enters the transferCapsule function before the state changes are finalized. This allows the attacker to: 1) First transaction: Call transferCapsule to initiate the transfer, 2) During the external call, re-enter and call transferCapsule again before withdrawnTime is set, 3) This can lead to double-spending where the same capsule is transferred multiple times while the state still shows it as available. The vulnerability is stateful because it depends on the capsule's withdrawnTime remaining 0 across multiple calls, and requires multiple transactions to set up the attack scenario.
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
  struct Capsule {
    uint value;
    uint id;
    uint lockTime;
    uint unlockTime;
    uint withdrawnTime;
  }

  struct Depositor {
    uint numCapsules;
    mapping (uint => Capsule) capsules;
  }

  mapping (address => Depositor) depositors;

  uint public minDeposit = 1000000000000000;
  uint public minDuration = 0;
  uint public maxDuration = 157680000;
  uint public totalCapsules;
  uint public totalValue;
  uint public totalBuriedCapsules;

  // === FALLBACK INJECTION: Reentrancy ===
  // This function was added as a fallback when existing functions failed injection
  function transferCapsule(uint capsuleNumber, address recipient) {
    Capsule storage capsule = depositors[msg.sender].capsules[capsuleNumber];
    require(capsule.unlockTime <= block.timestamp);
    require(capsule.withdrawnTime == 0);
    require(recipient != address(0));
    require(recipient != msg.sender);
    // Transfer value to recipient through external call
    if (recipient.call.value(capsule.value)()) {
        // State changes after external call - vulnerable to reentrancy
        capsule.withdrawnTime = block.timestamp;
        totalBuriedCapsules--;
        // Create new capsule for recipient
        if (depositors[recipient].numCapsules <= 0) {
            depositors[recipient] = Depositor({ numCapsules: 0 });
        }
        Depositor storage recipientDepositor = depositors[recipient];
        recipientDepositor.numCapsules++;
        recipientDepositor.capsules[recipientDepositor.numCapsules] = Capsule({
            value: capsule.value,
            id: recipientDepositor.numCapsules,
            lockTime: block.timestamp,
            unlockTime: block.timestamp,
            withdrawnTime: 0
        });
        totalBuriedCapsules++;
    }
  }
  // === END FALLBACK INJECTION ===

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
  }

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
