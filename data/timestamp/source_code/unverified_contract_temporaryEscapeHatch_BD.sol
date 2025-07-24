/*
 * ===== SmartInject Injection Details =====
 * Function      : temporaryEscapeHatch
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 2 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Introduced a sophisticated timestamp dependence vulnerability that requires multiple transactions to exploit effectively. The vulnerability manifests through several attack vectors:
 * 
 * 1. **Timestamp Manipulation in Emergency Mode**: The function introduces an emergency bypass mechanism that relies on block.timestamp comparisons. Miners can manipulate timestamps within ~900 seconds to extend emergency windows or bypass cooldowns.
 * 
 * 2. **State Accumulation Vulnerability**: The escapeUsageCount state variable accumulates across transactions, creating opportunities for attackers to manipulate the timing of calls to avoid increasing cooldowns.
 * 
 * 3. **Multi-Transaction Exploitation Path**:
 *    - Transaction 1: Attacker observes emergency activation or triggers normal usage to set lastEscapeTime
 *    - Transaction 2-N: Miner collaborates to manipulate block timestamps across multiple blocks
 *    - Final Transaction: Exploit the manipulated timing to bypass intended security restrictions
 * 
 * 4. **Required State Variables** (to be added to contract):
 *    - uint256 public lastEscapeTime;
 *    - uint256 public escapeCooldown = 1 hours;
 *    - uint256 public escapeUsageCount;
 *    - bool public emergencyActivated;
 *    - uint256 public emergencyActivatedAt;
 *    - uint256 public emergencyWindow = 24 hours;
 * 
 * The vulnerability is realistic because emergency escape hatches commonly implement time-based restrictions for security, but the reliance on block.timestamp makes them vulnerable to miner manipulation across multiple blocks.
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

  // Declarations for variables needed in temporaryEscapeHatch
  uint256 public lastEscapeTime;
  uint256 public escapeCooldown;
  uint256 public escapeUsageCount;
  bool public emergencyActivated;
  uint256 public emergencyActivatedAt;
  uint256 public emergencyWindow;

  function Distribution(address _admin, ERC20 _tokenContract,
                        bytes32[] _contributionHashes, uint256 _expectedTotalTokens) public {
    expectedTotalTokens = _expectedTotalTokens;
    contributionHashes = _contributionHashes;
    tokenContract = _tokenContract;
    admin = _admin;

    state = State.AwaitingTokens;
    // Initialize escape-related variables
    lastEscapeTime = 0;
    escapeCooldown = 0;
    escapeUsageCount = 0;
    emergencyActivated = false;
    emergencyActivatedAt = 0;
    emergencyWindow = 1 days; // example default
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
    // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
    
    // Time-based access control with cooldown mechanism
    require(block.timestamp >= lastEscapeTime + escapeCooldown);
    
    // Allow bypass if within emergency window (vulnerable to timestamp manipulation)
    if (emergencyActivated && block.timestamp <= emergencyActivatedAt + emergencyWindow) {
        lastEscapeTime = block.timestamp;
        require(to.call.value(value)(data));
        return;
    }
    
    // Normal operation with state updates
    lastEscapeTime = block.timestamp;
    escapeUsageCount++;
    
    // Increase cooldown based on usage frequency (state accumulation)
    if (escapeUsageCount > 3) {
        escapeCooldown = 1 days * escapeUsageCount; // Exponential backoff
    }
    
    require(to.call.value(value)(data));
}
    // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
}
