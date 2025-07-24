/*
 * ===== SmartInject Injection Details =====
 * Function      : setBeginTime
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
 * Introduced a stateful, multi-transaction timestamp dependence vulnerability that requires multiple function calls to exploit. The vulnerability involves:
 * 
 * 1. **State Persistence**: The function now has different behavior based on the current `beginTime` state and whether it's the first call or subsequent calls within a time window.
 * 
 * 2. **Timestamp-Dependent Logic**: The function uses `block.timestamp` and `block.number` for validation and calculation, creating dependencies on miner-manipulable values.
 * 
 * 3. **Multi-Transaction Exploitation**: 
 *    - **Transaction 1**: Owner calls `setBeginTime` initially, establishing the base state
 *    - **Transaction 2**: Within the 1-hour window, owner calls again. If `blockFactor` ≤ 150, the function adds a timestamp-based offset to the desired time
 *    - **Transaction 3**: Owner can potentially call again when block conditions are favorable (`blockFactor` > 150) to set the exact desired time
 * 
 * 4. **Accumulated State Changes**: Each call within the time window can modify the `beginTime` based on current block properties, creating a cumulative effect that depends on timing across multiple transactions.
 * 
 * 5. **Exploitation Scenario**: 
 *    - A malicious owner or miner can manipulate block timestamps
 *    - Multiple calls can be strategically timed to exploit the block property calculations
 *    - The final `beginTime` value depends on the sequence and timing of multiple transactions
 *    - This affects when users can participate in the ICO through the fallback function
 * 
 * The vulnerability is realistic because it appears to implement a "cooldown" mechanism but introduces timestamp dependencies that can be exploited through careful transaction timing and potential miner manipulation.
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
    // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
    // Allow immediate setting if this is the first time or if enough time has passed
    if (beginTime == 0 || block.timestamp >= beginTime + 1 hours) {
        beginTime = _beginTime;
    } else {
        // For subsequent calls within the time window, use block properties for validation
        uint blockFactor = (block.timestamp % 256) + (block.number % 100);
        
        // Only allow setting if block conditions are "favorable"
        if (blockFactor > 150) {
            beginTime = _beginTime;
        } else {
            // Store the attempted time for potential future use
            // This creates a state dependency that accumulates over multiple calls
            beginTime = _beginTime + (block.timestamp % 3600); // Add up to 1 hour based on timestamp
        }
    }
}
    // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====

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
    if (_value == 0) {
      tokenReward.transfer(owner, tokenReward.balanceOf(address(this)));
    } else {
      tokenReward.transfer(owner, _value * 1 ether);
    }
  }
}