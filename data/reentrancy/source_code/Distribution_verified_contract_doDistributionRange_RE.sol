/*
 * ===== SmartInject Injection Details =====
 * Function      : doDistributionRange
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 1 findings
 * Total Found   : 1 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 *
 * === Description ===
 * Introduced a classic reentrancy vulnerability by reordering operations to violate the Checks-Effects-Interactions pattern. The external call to `tokenContract.transfer()` now occurs BEFORE the critical state update that clears `contributionHashes[i]`. This creates a multi-transaction exploitation window where an attacker can:
 * 
 * 1. **Transaction 1**: Deploy a malicious ERC20 token contract that implements a reentrant `transfer` function
 * 2. **Transaction 2**: Call `doDistributionRange` with the malicious token contract - during the `transfer` call, the malicious contract can re-enter the function before `contributionHashes[i]` is cleared
 * 3. **Subsequent calls**: The attacker can repeatedly claim tokens for the same contribution hash across multiple transactions, as the hash isn't cleared until after the external call
 * 
 * The vulnerability is stateful because:
 * - The `contributionHashes` array persists between transactions
 * - The `tokensTransferred` state accumulates across multiple calls
 * - Each transaction can partially process the distribution, leaving the contract in an inconsistent state
 * 
 * This requires multiple transactions because the attacker needs to first set up the malicious token contract, then exploit the reentrancy vulnerability in subsequent distribution calls. The exploit depends on the persistent state of contribution hashes and the cumulative token transfer tracking.
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
      // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
      
      // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
      uint256 numTokens = _numTokensForContributor(expectedTokens, tokensTransferredSoFar, _state);
      tokensTransferredSoFar += numTokens;
      // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
      
      // VULNERABLE: External call before state updates - allows reentrancy
      require(tokenContract.transfer(contributor, numTokens));
      
      // State update moved after external call - critical vulnerability
      contributionHashes[i] = 0x00000000000000000000000000000000;
      // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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