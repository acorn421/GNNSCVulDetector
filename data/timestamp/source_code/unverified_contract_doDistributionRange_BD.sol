/*
 * ===== SmartInject Injection Details =====
 * Function      : doDistributionRange
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
 * Introduced timestamp dependence vulnerability through time-based early distribution bonuses and automatic state transitions. The vulnerability requires multiple transactions to exploit because:
 * 
 * 1. **State Accumulation**: The distributionStartTime is set on the first distribution call and persists across all subsequent calls. Attackers need multiple distribution transactions to manipulate the timing advantage.
 * 
 * 2. **Multi-Transaction Timing Manipulation**: Miners/validators can manipulate block.timestamp across multiple distribution calls to:
 *    - Delay the first distribution call to set a favorable distributionStartTime
 *    - Accelerate subsequent distribution calls to maximize early bonuses
 *    - Manipulate the 7-day auto-completion deadline
 * 
 * 3. **Exploitable Scenarios**:
 *    - Transaction 1: Attacker influences distributionStartTime by controlling when the first distribution occurs
 *    - Transactions 2-N: Attacker manipulates timestamps in subsequent distribution calls to maximize bonuses
 *    - The bonus calculation allows attackers to receive 10-20% extra tokens based on timing
 *    - Automatic state transition after 7 days can be manipulated to prevent legitimate distributions
 * 
 * 4. **Realistic Business Logic**: Time-based bonuses for early participation are common in token distributions, making this vulnerability pattern realistic and subtle.
 * 
 * The vulnerability cannot be exploited in a single transaction because it requires the establishment of distributionStartTime in one transaction and subsequent manipulation across multiple distribution calls to gain maximum advantage.
 */
pragma solidity ^0.4.18;

interface ERC20 {
    function balanceOf(address _owner) public constant returns (uint256 balance);
    function transfer(address _to, uint256 _value) public returns (bool success);
}

library SafeMath {
  function mul(uint256 a, uint256 b) internal pure returns (uint256) {
    if (a == 0) {
      return 0;
    }
    uint256 c = a * b;
    require(c / a == b);
    return c;
  }
}

contract Distribution {
  using SafeMath for uint256;

  enum State {
    AwaitingTokens,
    DistributingNormally,
    DistributingProRata,
    Done
  }
 
  address admin;
  ERC20 tokenContract;
  State public state;
  uint256 actualTotalTokens;
  uint256 tokensTransferred;

  bytes32[] contributionHashes;
  uint256 expectedTotalTokens;
  
  // ===== Added missing declaration =====
  uint256 distributionStartTime;

  constructor(address _admin, ERC20 _tokenContract,
                        bytes32[] _contributionHashes, uint256 _expectedTotalTokens) public {
    expectedTotalTokens = _expectedTotalTokens;
    contributionHashes = _contributionHashes;
    tokenContract = _tokenContract;
    admin = _admin;

    state = State.AwaitingTokens;
  }

  function _handleTokensReceived(uint256 totalTokens) internal {
    require(state == State.AwaitingTokens);
    require(totalTokens > 0);

    tokensTransferred = 0;
    if (totalTokens == expectedTotalTokens) {
      state = State.DistributingNormally;
    } else {
      actualTotalTokens = totalTokens;
      state = State.DistributingProRata;
    }
  }

  function handleTokensReceived() public {
    _handleTokensReceived(tokenContract.balanceOf(this));
  }

  function tokenFallback(address /*_from*/, uint _value, bytes /*_data*/) public {
    require(msg.sender == address(tokenContract));
    _handleTokensReceived(_value);
  }

  function _numTokensForContributor(uint256 contributorExpectedTokens,
                                    uint256 _tokensTransferred, State _state)
      internal view returns (uint256) {
    if (_state == State.DistributingNormally) {
      return contributorExpectedTokens;
    } else if (_state == State.DistributingProRata) {
      uint256 tokens = actualTotalTokens.mul(contributorExpectedTokens) / expectedTotalTokens;

      uint256 tokensRemaining = actualTotalTokens - _tokensTransferred;
      if (tokens < tokensRemaining) {
        return tokens;
      } else {
        return tokensRemaining;
      }
    } else {
      revert();
    }
  }

  function doDistributionRange(uint256 start, address[] contributors,
                               uint256[] contributorExpectedTokens) public {
    require(contributors.length == contributorExpectedTokens.length);

    uint256 tokensTransferredSoFar = tokensTransferred;
    uint256 end = start + contributors.length;
    State _state = state;
    // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
    
    // Track distribution timing for early contributor bonus calculation
    if (distributionStartTime == 0) {
        distributionStartTime = block.timestamp;
    }
    
    // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
    for (uint256 i = start; i < end; ++i) {
      address contributor = contributors[i];
      uint256 expectedTokens = contributorExpectedTokens[i];
      require(contributionHashes[i] == keccak256(contributor, expectedTokens));
      contributionHashes[i] = 0x00000000000000000000000000000000;

      uint256 numTokens = _numTokensForContributor(expectedTokens, tokensTransferredSoFar, _state);
      // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
      
      // Apply time-based early distribution bonus
      uint256 distributionDuration = block.timestamp - distributionStartTime;
      if (distributionDuration <= 86400) { // Within 24 hours
          uint256 bonusMultiplier = 110 + (86400 - distributionDuration) / 8640; // 10-20% bonus
          numTokens = numTokens * bonusMultiplier / 100;
      }
      
      // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
      tokensTransferredSoFar += numTokens;
      require(tokenContract.transfer(contributor, numTokens));
    }

    tokensTransferred = tokensTransferredSoFar;
    // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
    
    // Automatically transition to Done state after 7 days regardless of tokens remaining
    if (block.timestamp >= distributionStartTime + 604800) {
        state = State.Done;
    } else if (tokensTransferred == actualTotalTokens) {
        state = State.Done;
    // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
    }
  }

  function numTokensForContributor(uint256 contributorExpectedTokens)
      public view returns (uint256) {
    return _numTokensForContributor(contributorExpectedTokens, tokensTransferred, state);
  }

  function temporaryEscapeHatch(address to, uint256 value, bytes data) public {
    require(msg.sender == admin);
    require(to.call.value(value)(data));
  }
}
