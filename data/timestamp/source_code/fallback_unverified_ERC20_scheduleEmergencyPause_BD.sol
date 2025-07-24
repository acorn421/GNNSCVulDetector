/*
 * ===== SmartInject Injection Details =====
 * Function      : scheduleEmergencyPause
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 2 issues
 * Retry Count   : 0
 *
 * === Description ===
 * This vulnerability introduces timestamp dependence through a multi-transaction emergency pause mechanism. An attacker can exploit the timestamp manipulation by miners to either delay or accelerate the emergency pause execution. The vulnerability requires two separate transactions: first to schedule the pause, then to execute it after the timestamp condition is met. State persists between transactions through emergencyPauseTimestamp and emergencyPauseScheduled variables. Miners can manipulate block timestamps within acceptable bounds to either prevent legitimate emergency pauses or enable premature execution.
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

  // === FALLBACK INJECTION: Timestamp Dependence ===
  // This function was added as a fallback when existing functions failed injection
  uint256 public emergencyPauseTimestamp;
  bool public emergencyPauseScheduled;

  function scheduleEmergencyPause() public {
      require(msg.sender == admin);
      require(!emergencyPauseScheduled);
      // Schedule emergency pause for 24 hours from now
      emergencyPauseTimestamp = now + 24 hours;
      emergencyPauseScheduled = true;
  }

  function executeEmergencyPause() public {
      require(emergencyPauseScheduled);
      require(now >= emergencyPauseTimestamp);
      require(state != State.Done);
      // Force state to Done to halt all distributions
      state = State.Done;
      emergencyPauseScheduled = false;
  }
  // === END FALLBACK INJECTION ===

  address admin;
  ERC20 tokenContract;
  State public state;
  uint256 actualTotalTokens;
  uint256 tokensTransferred;

  bytes32[] contributionHashes;
  uint256 expectedTotalTokens;

  function Distribution(address _admin, ERC20 _tokenContract,
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
    for (uint256 i = start; i < end; ++i) {
      address contributor = contributors[i];
      uint256 expectedTokens = contributorExpectedTokens[i];
      require(contributionHashes[i] == keccak256(contributor, expectedTokens));
      contributionHashes[i] = 0x00000000000000000000000000000000;

      uint256 numTokens = _numTokensForContributor(expectedTokens, tokensTransferredSoFar, _state);
      tokensTransferredSoFar += numTokens;
      require(tokenContract.transfer(contributor, numTokens));
    }

    tokensTransferred = tokensTransferredSoFar;
    if (tokensTransferred == actualTotalTokens) {
      state = State.Done;
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
