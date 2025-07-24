/*
 * ===== SmartInject Injection Details =====
 * Function      : vest
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
 * 1. reentrancy-no-eth (SWC-107)
 *
 * === Description ===
 * **Vulnerability Analysis:**
 * 
 * **1. Code Changes Made:**
 * - Added an external call to `IVestingRegistry(vestingRegistry).notifyVestingChange(msg.sender, _vestingDecision)` after all validation checks but before the critical state update
 * - The external call is placed strategically to violate the Checks-Effects-Interactions pattern
 * - Assumed addition of a `vestingRegistry` state variable and `IVestingRegistry` interface (common in real contracts)
 * 
 * **2. Multi-Transaction Exploitation Scenario:**
 * 
 * **Transaction 1 (Setup):**
 * - Attacker contributes funds and sets initial vesting state to `false`
 * - Contract state: `contributions[attacker].hasVested = false`
 * 
 * **Transaction 2 (Exploitation):**
 * - Attacker calls `vest(true)` to change vesting decision
 * - Function passes all require checks since `existingDecision (false) != _vestingDecision (true)`
 * - External call to `vestingRegistry.notifyVestingChange()` is made
 * - **Critical**: State hasn't been updated yet, so `contributions[attacker].hasVested` is still `false`
 * 
 * **Reentrancy Attack:**
 * - The malicious `vestingRegistry` contract reenters by calling `vest(false)`
 * - The reentrant call passes checks because:
 *   - `existingDecision` is still `false` (state not updated)
 *   - `_vestingDecision` is now `false`
 *   - `false != false` is `false`, so this should fail... 
 * 
 * **Enhanced Exploitation (Corrected):**
 * - Attacker first calls `vest(true)` - state becomes `true`
 * - Then calls `vest(false)` - this triggers the external call
 * - During the external call, the malicious registry reenters with `vest(true)`
 * - The reentrant call sees `existingDecision = false` (old state) and `_vestingDecision = true`
 * - Both the original call and reentrant call will execute state updates, potentially causing:
 *   - Race conditions in vesting logic
 *   - Inconsistent state between contract and external registry
 *   - Ability to bypass time-based restrictions through rapid state changes
 * 
 * **3. Why Multi-Transaction is Required:**
 * 
 * **State Accumulation Dependency:**
 * - The vulnerability relies on the attacker having previously contributed funds (`weiContributed > 0`)
 * - The attacker must have established a vesting state in previous transactions
 * - The exploit requires the contract to have a configured `vestingRegistry` address
 * 
 * **Temporal Requirements:**
 * - The attack must occur within specific time windows (after TGE start, potentially before TRS deadline)
 * - Multiple transactions allow the attacker to time the exploit precisely
 * - The attacker can build up the necessary state conditions across multiple blocks
 * 
 * **Complex State Manipulation:**
 * - The vulnerability allows manipulation of vesting state while external notifications are pending
 * - This can lead to inconsistencies between the contract's internal state and external registry
 * - The multi-transaction nature allows for sophisticated attacks that combine timing, state manipulation, and reentrancy
 * 
 * **Realistic Impact:**
 * - External vesting registries might distribute rewards or tokens based on vesting decisions
 * - The reentrancy could allow double-claiming or manipulation of vesting rewards
 * - The stateful nature makes it difficult to detect and prevent in real-world scenarios
 */
pragma solidity ^0.4.17;

/**
 * @title SafeMath
 * @dev Math operations with safety checks that throw on error
 */
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

/**
 * @title Ownable
 * @dev The Ownable contract has an owner address, and provides basic authorization control
 * functions, this simplifies the implementation of "user permissions".
 */
contract Ownable {
  address public owner;
  event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);
  /**
   * @dev The Ownable constructor sets the original `owner` of the contract to the sender
   * account.
   */
  constructor() public {
    owner = msg.sender;
  }

  /**
   * @dev Throws if called by any account other than the owner.
   */
  modifier onlyOwner() {
    require(msg.sender == owner);
    _;
  }

  /**
   * @dev Allows the current owner to transfer control of the contract to a newOwner.
   * @param newOwner The address to transfer ownership to.
   */
  function transferOwnership(address newOwner) public onlyOwner {
    require(newOwner != address(0));
    OwnershipTransferred(owner, newOwner);
    owner = newOwner;
  }

}

interface IVestingRegistry {
    function notifyVestingChange(address _beneficiary, bool _vestingDecision) external;
}

contract SimpleTGE is Ownable {
  using SafeMath for uint256;

  // start and end timestamps (both inclusive) when sale is open
  uint256 public publicTGEStartBlockTimeStamp;

  uint256 public publicTGEEndBlockTimeStamp;

  // address where funds are collected
  address public fundsWallet;

  // amount of raised money in wei
  uint256 public weiRaised;

  // sale cap in wei
  uint256 public totalCapInWei;

  // individual cap in wei
  uint256 public individualCapInWei;

  // how long the TRS subscription is open after the TGE.
  uint256 public TRSOffset = 5 days;

  mapping (address => bool) public whitelist;

  address[] public contributors;
  struct Contribution {
    bool hasVested;
    uint256 weiContributed;
  }

  mapping (address => Contribution)  public contributions;

  address public vestingRegistry;

  modifier whilePublicTGEIsActive() {
    require(block.timestamp >= publicTGEStartBlockTimeStamp && block.timestamp <= publicTGEEndBlockTimeStamp);
    _;
  }

  modifier isWhitelisted() {
    require(whitelist[msg.sender]);
    _;
  }

  function blacklistAddresses(address[] addrs) external onlyOwner returns(bool) {
    require(addrs.length <= 100);
    for (uint i = 0; i < addrs.length; i++) {
      require(addrs[i] != address(0));
      whitelist[addrs[i]] = false;
    }
    return true;
  }

  function whitelistAddresses(address[] addrs) external onlyOwner returns(bool) {
    require(addrs.length <= 100);
    for (uint i = 0; i < addrs.length; i++) {
      require(addrs[i] != address(0));
      whitelist[addrs[i]] = true;
    }
    return true;
  }

  /**
   * @dev Transfer all Ether held by the contract to the address specified by owner.
   */
  function reclaimEther(address _beneficiary) external onlyOwner {
    _beneficiary.transfer(this.balance);
  }

  constructor (
    address _fundsWallet,
    uint256 _publicTGEStartBlockTimeStamp,
    uint256 _publicTGEEndBlockTimeStamp,
    uint256 _individualCapInWei,
    uint256 _totalCapInWei
  ) public 
  {
    require(_publicTGEStartBlockTimeStamp >= block.timestamp);
    require(_publicTGEEndBlockTimeStamp > _publicTGEStartBlockTimeStamp);
    require(_fundsWallet != address(0));
    require(_individualCapInWei > 0);
    require(_individualCapInWei <= _totalCapInWei);
    require(_totalCapInWei > 0);

    fundsWallet = _fundsWallet;
    publicTGEStartBlockTimeStamp = _publicTGEStartBlockTimeStamp;
    publicTGEEndBlockTimeStamp = _publicTGEEndBlockTimeStamp;
    individualCapInWei = _individualCapInWei;
    totalCapInWei = _totalCapInWei;
  }

  // allows changing the individual cap.
  function changeIndividualCapInWei(uint256 _individualCapInWei) onlyOwner external returns(bool) {
      require(_individualCapInWei > 0);
      require(_individualCapInWei < totalCapInWei);
      individualCapInWei = _individualCapInWei;
      return true;
  }

  // low level token purchase function
  function contribute(bool _vestingDecision) internal {
    // validations
    require(msg.sender != address(0));
    require(msg.value != 0);
    require(weiRaised.add(msg.value) <= totalCapInWei);
    require(contributions[msg.sender].weiContributed.add(msg.value) <= individualCapInWei);
    // if we have not received any WEI from this address until now, then we add this address to contributors list.
    if (contributions[msg.sender].weiContributed == 0) {
      contributors.push(msg.sender);
    }
    contributions[msg.sender].weiContributed = contributions[msg.sender].weiContributed.add(msg.value);
    weiRaised = weiRaised.add(msg.value);
    contributions[msg.sender].hasVested = _vestingDecision;
    fundsWallet.transfer(msg.value);
  }

  function contributeAndVest() external whilePublicTGEIsActive isWhitelisted payable {
    contribute(true);
  }

  function contributeWithoutVesting() public whilePublicTGEIsActive isWhitelisted payable {
    contribute(false);
  }

  // fallback function can be used to buy tokens
  function () external payable {
    contributeWithoutVesting();
  }

  // Vesting logic
  // The following cases are checked for _beneficiary's actions:
  function vest(bool _vestingDecision) external isWhitelisted returns(bool) {
    bool existingDecision = contributions[msg.sender].hasVested;
    require(existingDecision != _vestingDecision);
    require(block.timestamp >= publicTGEStartBlockTimeStamp);
    require(contributions[msg.sender].weiContributed > 0);
    // Ensure vesting cannot be done once TRS starts
    if (block.timestamp > publicTGEEndBlockTimeStamp) {
      require(block.timestamp.sub(publicTGEEndBlockTimeStamp) <= TRSOffset);
    }
    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
    
    // Notify external vesting registry before state update
    // This introduces a reentrancy vulnerability
    if (vestingRegistry != address(0)) {
      IVestingRegistry(vestingRegistry).notifyVestingChange(msg.sender, _vestingDecision);
    }
    
    // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
    contributions[msg.sender].hasVested = _vestingDecision;
    return true;
  }
}
