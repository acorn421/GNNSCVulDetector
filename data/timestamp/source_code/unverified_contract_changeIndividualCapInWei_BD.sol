/*
 * ===== SmartInject Injection Details =====
 * Function      : changeIndividualCapInWei
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
 * This vulnerability introduces timestamp dependence through a multi-transaction "emergency cap increase" mechanism that can be manipulated by miners or through timestamp manipulation:
 * 
 * **Multi-Transaction Exploitation Path:**
 * 
 * **Transaction 1 (Setup):** 
 * - Owner calls changeIndividualCapInWei() when block.timestamp % 256 == 0 (critical moment)
 * - This stores a pendingCapChange instead of immediately applying it
 * - The pending change is stored with the current block.timestamp
 * 
 * **Transaction 2+ (Exploitation):**
 * - In subsequent transactions, when enough time has passed (>=1 second), the pending cap change can be applied
 * - If the pending cap is higher than the current cap, it gets applied unconditionally
 * - Contributors can then exploit the higher individual cap in their contribution transactions
 * 
 * **Why This Requires Multiple Transactions:**
 * 1. The vulnerability requires the first transaction to occur at a "critical moment" (timestamp divisible by 256)
 * 2. The actual cap increase only takes effect in subsequent transactions after the time delay
 * 3. The exploitation requires contributors to make contribution calls after the cap has been increased
 * 4. The state (pendingCapChange, capChangeTimestamp) persists between transactions, enabling the multi-step attack
 * 
 * **Timestamp Dependence Issues:**
 * - Miners can manipulate block.timestamp to hit the "critical moment" condition
 * - The modulo operation makes the timing predictable for attackers
 * - Time-based delays can be manipulated through timestamp manipulation
 * - The condition creates a dependency on block.timestamp for critical security logic
 * 
 * **Required Additional State Variables:**
 * - uint256 pendingCapChange;
 * - uint256 capChangeTimestamp;
 * 
 * This creates a realistic vulnerability where administrative emergency features depend on timestamp conditions that can be exploited across multiple transactions.
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
  function Ownable() public {
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

  // VULNERABILITY STATE VARIABLES
  uint256 public pendingCapChange;
  uint256 public capChangeTimestamp;

  // how long the TRS subscription is open after the TGE.
  uint256 public TRSOffset = 5 days;

  mapping (address => bool) public whitelist;

  address[] public contributors;
  struct Contribution {
    bool hasVested;
    uint256 weiContributed;
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
    _beneficiary.transfer(this.balance);
  }

  function SimpleTGE (
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
      // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
      
      // Allow emergency cap increases during critical time windows
      // This creates timestamp dependence vulnerability
      if (block.timestamp % 256 == 0) {
          // During "critical moments" (when block.timestamp is divisible by 256),
          // store the timestamp for delayed cap activation
          pendingCapChange = _individualCapInWei;
          capChangeTimestamp = block.timestamp;
          return true;
      }
      
      // If there's a pending cap change and enough time has passed since the critical moment
      if (pendingCapChange > 0 && block.timestamp > capChangeTimestamp && 
          block.timestamp - capChangeTimestamp >= 1) {
          // Apply the higher of current cap or pending cap change
          if (pendingCapChange > individualCapInWei) {
              individualCapInWei = pendingCapChange;
          } else {
              individualCapInWei = _individualCapInWei;
          }
          pendingCapChange = 0;
          capChangeTimestamp = 0;
      } else {
          individualCapInWei = _individualCapInWei;
      }
      
      // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
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
    contributions[msg.sender].hasVested = _vestingDecision;
    return true;
  }
}