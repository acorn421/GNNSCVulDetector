/*
 * ===== SmartInject Injection Details =====
 * Function      : WithdrawalToken
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
 * Introduced a stateful, multi-transaction Timestamp Dependence vulnerability by implementing a withdrawal cooldown mechanism that relies on block.timestamp. The vulnerability requires multiple transactions to exploit:
 * 
 * **Specific Changes Made:**
 * 1. Added implicit state variables `lastWithdrawalTime` and `withdrawalCooldown` (would need to be declared in contract)
 * 2. Implemented cooldown initialization on first withdrawal
 * 3. Added timestamp-based cooldown enforcement using `block.timestamp`
 * 4. Updated withdrawal timestamp after successful withdrawal
 * 
 * **Multi-Transaction Exploitation Process:**
 * 1. **Transaction 1 (Setup)**: Owner performs first withdrawal, initializing `lastWithdrawalTime` with current `block.timestamp`
 * 2. **Transaction 2+ (Exploitation)**: Miner manipulates `block.timestamp` in subsequent blocks to bypass the 24-hour cooldown period
 * 
 * **Why Multi-Transaction is Required:**
 * - The vulnerability requires establishing an initial state (`lastWithdrawalTime`) in the first transaction
 * - Subsequent transactions can exploit timestamp manipulation to bypass cooldown periods
 * - Each withdrawal updates the state, creating persistent conditions for future exploits
 * - The exploit cannot occur in a single transaction because it depends on the sequence of withdrawal attempts and timestamp manipulation across multiple blocks
 * 
 * **Exploitation Scenario:**
 * A malicious miner could:
 * 1. Process initial withdrawal with manipulated timestamp
 * 2. In subsequent blocks, adjust `block.timestamp` to make it appear that sufficient time has passed
 * 3. Allow premature withdrawals that violate the intended 24-hour cooldown restriction
 * 4. Repeat this process to drain tokens faster than intended by the business logic
 * 
 * This creates a realistic timestamp dependence vulnerability that requires multiple transactions and persistent state changes to exploit.
 */
pragma solidity ^0.4.18;

library SafeMath {
  function mul(uint256 a, uint256 b) pure internal returns (uint256) {
    uint256 c = a * b;
    assert(a == 0 || c / a == b);
    return c;
  }
}

contract token {
  mapping (address => uint256) public balanceOf;
  function transfer(address _to, uint256 _value) external;
}

contract ICOCrowdsale {
  using SafeMath for uint256;
  token public tokenReward;
  mapping(address => uint256) public balanceOf;

  uint public beginTime;
  uint public endTime;
  
  address public owner;
  // Added state variables for withdrawal timestamp logic
  uint public lastWithdrawalTime;
  uint public withdrawalCooldown;

  event Transfer(address indexed _from, uint256 _value);

  constructor (
    address ICOReward,
    uint _beginTime,
    uint _endTime
  ) payable public {
    tokenReward = token(ICOReward);
    beginTime = _beginTime;
    endTime = _endTime;

    owner = msg.sender;
  }

  function () payable public{
    uint amount = msg.value;

    require(amount % 10 ** 17 == 0);
    require(now >= beginTime && now <= endTime);
    tokenReward.transfer(msg.sender, amount.mul(1000));

    emit Transfer(msg.sender, amount);
  }

  function setBeginTime(uint _beginTime) onlyOwner public {
    beginTime = _beginTime;
  }

  function setEndTime(uint _endTime) onlyOwner public {
    endTime = _endTime;
  }

  modifier onlyOwner {
    require(msg.sender == owner);
    _;
  }

  function WithdrawalETH(uint _value) onlyOwner public {
    if (_value == 0)
      owner.transfer(address(this).balance);
    else
      owner.transfer(_value * 1 ether);
  }

  function WithdrawalToken(uint _value) onlyOwner public {
    // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
    // Initialize withdrawal cooldown on first use
    if (lastWithdrawalTime == 0) {
      lastWithdrawalTime = block.timestamp;
      withdrawalCooldown = 86400; // 24 hours in seconds
    }
    
    // Enforce withdrawal cooldown using block.timestamp
    require(block.timestamp >= lastWithdrawalTime + withdrawalCooldown, "Withdrawal cooldown period not met");
    // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
    if (_value == 0) {
      tokenReward.transfer(owner, tokenReward.balanceOf(address(this)));
    } else {
      tokenReward.transfer(owner, _value * 1 ether);
    }
    // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
    
    // Update last withdrawal time for next cooldown period
    lastWithdrawalTime = block.timestamp;
    // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
  }
}
