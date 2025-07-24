/*
 * ===== SmartInject Injection Details =====
 * Function      : creditTokens
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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by:
 * 
 * 1. **Adding State Updates After External Calls**: The function now updates the `released` mapping AFTER making external calls to the token contract, violating the Checks-Effects-Interactions pattern.
 * 
 * 2. **Creating Stateful Dependency**: The vulnerability depends on the `released` mapping which persists between transactions and can be manipulated during reentrancy.
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 
 * **Transaction 1**: An attacker deploys a malicious token contract and somehow gets it set as the `tokenContract` (through a separate vulnerability or social engineering).
 * 
 * **Transaction 2**: The attacker calls the fallback function multiple times to become a payee with significant shares allocation.
 * 
 * **Transaction 3**: The owner calls `creditTokens()`, which triggers the vulnerability:
 * - The function calls the malicious token contract's `transferFrom` method
 * - The malicious contract re-enters `creditTokens()` before the `released` state is updated
 * - Since `released[payees[i]]` hasn't been updated yet, the attacker can manipulate state or trigger additional operations
 * - The re-entrant call processes the same payee again before the original call completes its state update
 * 
 * **Why Multi-Transaction is Required:**
 * - **Transaction 1**: Attacker must first become a payee through the fallback function
 * - **Transaction 2**: Owner must call `creditTokens()` to trigger the vulnerable external call
 * - **State Persistence**: The `released` mapping carries state between transactions, enabling the attacker to exploit the timing window between external calls and state updates
 * - **Loop Amplification**: Each payee in the loop creates a new reentrancy opportunity, making the attack more severe with accumulated state
 * 
 * This creates a realistic vulnerability where an attacker must first establish themselves as a payee, then wait for the owner to trigger the vulnerable function, making it inherently multi-transaction and stateful.
 */
pragma solidity ^0.4.13;

library SafeMath {
  function mul(uint256 a, uint256 b) internal pure returns (uint256) {
    if (a == 0) {
      return 0;
    }
    uint256 c = a * b;
    assert(c / a == b);
    return c;
  }

  function div(uint256 a, uint256 b) internal pure returns (uint256) {
    // assert(b > 0); // Solidity automatically throws when dividing by 0
    uint256 c = a / b;
    // assert(a == b * c + a % b); // There is no case in which this doesn't hold
    return c;
  }

  function sub(uint256 a, uint256 b) internal pure returns (uint256) {
    assert(b <= a);
    return a - b;
  }

  function add(uint256 a, uint256 b) internal pure returns (uint256) {
    uint256 c = a + b;
    assert(c >= a);
    return c;
  }
}

contract EnjinGiveaway {
  using SafeMath for uint256;

  uint256 public totalShares = 1000000;
  uint256 public totalReleased = 0;

  mapping(address => uint256) public shares;
  mapping(address => uint256) public released;
  address[] public payees;
  address public owner;
  address public tokenContract;
  
  /**
   * @dev Constructor
   */
  function EnjinGiveaway() public {
    owner = msg.sender;
    tokenContract = 0xF629cBd94d3791C9250152BD8dfBDF380E2a3B9c;
  }

  /**
   * @dev Add a new payee to the contract.
   * @param _payee The address of the payee to add.
   * @param _shares The number of shares owned by the payee.
   */
  function addPayee(address _payee, uint256 _shares) internal {
    require(_payee != address(0));
    require(_shares > 0);
    require(shares[_payee] == 0);

    payees.push(_payee);
    shares[_payee] = _shares;
  }
  
  function () payable {
      require(totalReleased < totalShares);
      uint256 amount = msg.sender.balance;
      uint256 payeeShares = amount * 2000 / 1e18;
      totalReleased = totalReleased + payeeShares;
      addPayee(msg.sender, payeeShares);
      owner.transfer(msg.value);
  }

  function creditTokens() public {
    require(msg.sender == owner);
    
    for (uint i=0; i < payees.length; i++) {
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // Make external call to potentially malicious token contract before updating state
        bool success = tokenContract.call(bytes4(sha3("transferFrom(address,address,uint256)")), this, payees[i], shares[payees[i]]);
        
        // State update happens AFTER external call - vulnerable to reentrancy
        if (success) {
            released[payees[i]] = released[payees[i]].add(shares[payees[i]]);
        }
    }
}
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====    
}