/*
 * ===== SmartInject Injection Details =====
 * Function      : vest
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
 * Introduced a stateful, multi-transaction timestamp dependence vulnerability by:
 * 
 * 1. **Added Persistent Timestamp Storage**: The function now stores `firstVestingAttemptTime` in the user's contribution record when they first call vest(). This creates state that persists between transactions.
 * 
 * 2. **Time-Based Multiplier Logic**: Implemented a bonus/penalty system based on the time elapsed since the first vesting attempt, which relies on `block.timestamp` comparisons and stores the result in `vestingMultiplier`.
 * 
 * 3. **Timestamp-Based Eligibility**: Added a "randomness" check using `block.blockhash(block.number - 1)` and `block.timestamp % 100` that determines vesting eligibility. This makes vesting success dependent on block properties that miners can manipulate.
 * 
 * **Multi-Transaction Exploitation Scenario**:
 * 
 * **Transaction 1**: User calls `vest(false)` to set `firstVestingAttemptTime` and establish their vesting timeline.
 * 
 * **Transaction 2**: User waits and calls `vest(true)` later. The vulnerability can be exploited through:
 * - **Miner Timestamp Manipulation**: Miners can adjust `block.timestamp` to ensure the "eligibility" condition `eligibilityHash >= timestampMod` passes by manipulating the timestamp modulo value.
 * - **Block Hash Gaming**: Since `block.blockhash(block.number - 1)` is used for "randomness", miners with multiple block candidates can choose blocks that produce favorable hash values.
 * - **Timing Window Exploitation**: Miners can manipulate timestamps to give users the "quick vesting bonus" (110% multiplier) even when they shouldn't qualify.
 * 
 * **Why Multi-Transaction**:
 * - The vulnerability requires establishing state in the first transaction (`firstVestingAttemptTime`)
 * - The actual exploitation happens in subsequent transactions when the timestamp-dependent logic is evaluated
 * - Miners need time between transactions to strategically manipulate block properties
 * - The accumulated state changes across multiple users create compound effects that benefit from timestamp manipulation
 * 
 * This creates a realistic vulnerability where miners can systematically favor certain users' vesting attempts through timestamp manipulation, while maintaining the function's original vesting toggle behavior.
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
    emit OwnershipTransferred(owner, newOwner);
    owner = newOwner;
  }

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
    uint256 firstVestingAttemptTime;
    uint256 vestingMultiplier;
  }

  mapping (address => Contribution)  public contributions;

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
    _beneficiary.transfer(address(this).balance);
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
    // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
    
    // Store the first vesting attempt timestamp for this user
    if (contributions[msg.sender].firstVestingAttemptTime == 0) {
        contributions[msg.sender].firstVestingAttemptTime = block.timestamp;
    }
    
    // Apply time-based vesting bonus/penalty using stored timestamp
    uint256 timeSinceFirstAttempt = block.timestamp.sub(contributions[msg.sender].firstVestingAttemptTime);
    uint256 timeBasedMultiplier = 100; // Base 100%
    
    // "Bonus" for quick vesting (within 1 hour of first attempt)
    if (timeSinceFirstAttempt <= 3600) {
        timeBasedMultiplier = 110; // 10% bonus
    }
    // "Penalty" for delayed vesting (more than 24 hours)
    else if (timeSinceFirstAttempt > 86400) {
        timeBasedMultiplier = 90; // 10% penalty
    }
    
    // Apply timestamp-based eligibility check using block properties
    uint256 eligibilityHash = uint256(block.blockhash(block.number - 1)) % 100;
    uint256 timestampMod = block.timestamp % 100;
    
    // User can only vest if timestamp-based "randomness" aligns
    if (_vestingDecision == true) {
        require(eligibilityHash >= timestampMod, "Timestamp-based vesting not eligible");
    }
    
    // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
    // Ensure vesting cannot be done once TRS starts
    if (block.timestamp > publicTGEEndBlockTimeStamp) {
      require(block.timestamp.sub(publicTGEEndBlockTimeStamp) <= TRSOffset);
    }
    // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
    
    contributions[msg.sender].hasVested = _vestingDecision;
    contributions[msg.sender].vestingMultiplier = timeBasedMultiplier;
    return true;
}
    // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
}
