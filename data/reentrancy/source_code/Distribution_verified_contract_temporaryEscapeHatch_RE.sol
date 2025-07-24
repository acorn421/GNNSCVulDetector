/*
 * ===== SmartInject Injection Details =====
 * Function      : temporaryEscapeHatch
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 1 findings
 * Total Found   : 3 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-eth (SWC-107)
 *
 * === Description ===
 * Introduced stateful, multi-transaction reentrancy vulnerability by adding usage tracking with cooldown periods. The vulnerability requires multiple transactions to accumulate state that enables exploitation:
 * 
 * **State Changes Made:**
 * 1. Added `escapeHatchUsage` mapping to track cumulative usage per admin
 * 2. Added `lastEscapeTimestamp` mapping to track cooldown periods
 * 3. Added `escapeHatchCooldown` and `maxEscapePerCooldown` constants
 * 
 * **Multi-Transaction Exploitation Pattern:**
 * 1. **Transaction 1**: Admin calls escape hatch, partially fills usage limit and sets timestamp
 * 2. **Transaction 2**: After cooldown expires, admin calls again - usage tracking state becomes inconsistent
 * 3. **During External Call**: Malicious contract can reenter when state is partially updated but cooldown logic is incomplete
 * 
 * **Vulnerability Mechanism:**
 * - Usage is incremented before external call but cooldown reset happens after
 * - If external call reenters during cooldown expiry window, usage limits can be bypassed
 * - Requires time passage between transactions for cooldown to expire
 * - State accumulation across multiple calls creates exploitation opportunity
 * 
 * **Why Multi-Transaction is Required:**
 * - Cooldown mechanism requires real time passage between transactions
 * - Usage accumulation needs multiple calls to reach exploitable state
 * - Reentrancy window only opens when cooldown expires during external call execution
 * - Single transaction cannot manipulate both usage state and time-based cooldown simultaneously
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

  // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
mapping(address => uint256) public escapeHatchUsage;
  mapping(address => uint256) public lastEscapeTimestamp;
  uint256 public escapeHatchCooldown = 1 hours;
  uint256 public maxEscapePerCooldown = 1000 ether;

  function temporaryEscapeHatch(address to, uint256 value, bytes data) public {
    require(msg.sender == admin);
    
    // Check cooldown period has passed
    require(block.timestamp >= lastEscapeTimestamp[admin] + escapeHatchCooldown);
    
    // Check usage limit within cooldown period
    require(escapeHatchUsage[admin] + value <= maxEscapePerCooldown);
    
    // Update usage before external call - vulnerable to reentrancy
    escapeHatchUsage[admin] += value;
    
    // External call - potential reentrancy point
    require(to.call.value(value)(data));
    
    // State update after external call - this creates the vulnerability
    // If cooldown period expires during external call, this doesn't reset usage
    if (block.timestamp >= lastEscapeTimestamp[admin] + escapeHatchCooldown) {
      lastEscapeTimestamp[admin] = block.timestamp;
    }
// ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
  }
}