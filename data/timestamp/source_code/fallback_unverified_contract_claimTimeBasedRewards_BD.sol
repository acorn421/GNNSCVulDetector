/*
 * ===== SmartInject Injection Details =====
 * Function      : claimTimeBasedRewards
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 1 issues
 * Retry Count   : 0
 *
 * === Description ===
 * This vulnerability introduces a timestamp dependence issue in a time-based reward system. The vulnerability is stateful and multi-transaction because: 1) It requires an initial transaction to set the lastRewardClaim timestamp, 2) Subsequent transactions can exploit timestamp manipulation to claim rewards more frequently than intended, 3) The state persists between transactions through the lastRewardClaim mapping, 4) Multiple exploit transactions are needed to accumulate significant rewards, 5) The vulnerability becomes more valuable over time as reward balances accumulate. A malicious miner could manipulate block timestamps to reduce the apparent time between reward claims, allowing more frequent reward collection than the intended rewardPeriod.
 */
pragma solidity ^0.4.21;

/**
 * @title SafeMath
 * @dev Math operations with safety checks that throw on error
 */
library SafeMath {

  /**
  * @dev Multiplies two numbers, throws on overflow.
  */
  function mul(uint256 a, uint256 b) internal pure returns (uint256 c) {
    if (a == 0) {
      return 0;
    }
    c = a * b;
    assert(c / a == b);
    return c;
  }

  /**
  * @dev Integer division of two numbers, truncating the quotient.
  */
  function div(uint256 a, uint256 b) internal pure returns (uint256) {
    // assert(b > 0); // Solidity automatically throws when dividing by 0
    // uint256 c = a / b;
    // assert(a == b * c + a % b); // There is no case in which this doesn't hold
    return a / b;
  }

  /**
  * @dev Subtracts two numbers, throws on overflow (i.e. if subtrahend is greater than minuend).
  */
  function sub(uint256 a, uint256 b) internal pure returns (uint256) {
    assert(b <= a);
    return a - b;
  }

  /**
  * @dev Adds two numbers, throws on overflow.
  */
  function add(uint256 a, uint256 b) internal pure returns (uint256 c) {
    c = a + b;
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

contract WestrendWallet is Ownable {
    using SafeMath for uint256;

    // Address where funds are collected
    address public wallet = 0xe3de74151CbDFB47d214F7E6Bcb8F5EfDCf99636;
  
    // How many token units a buyer gets per wei
    uint256 public rate = 1100;

    // Minimum investment in wei (.20 ETH)
    uint256 public minInvestment = 2E17;

    // Maximum investment in wei  (2,000 ETH)
    uint256 public investmentUpperBounds = 2E21;

    // Hard cap in wei (100,000 ETH)
    uint256 public hardcap = 1E23;

    // Amount of wei raised
    uint256 public weiRaised;

    event TokenPurchase(address indexed beneficiary, uint256 value, uint256 amount);
    event Whitelist(address whiteaddress);
    event Blacklist(address blackaddress);
    event ChangeRate(uint256 newRate);
    event ChangeMin(uint256 newMin);
    event ChangeMax(uint256 newMax);

    /** Whitelist an address and set max investment **/
    mapping (address => bool) public whitelistedAddr;
    mapping (address => uint256) public totalInvestment;
  
    // === FALLBACK INJECTION: Timestamp Dependence ===
    // This function was added as a fallback when existing functions failed injection
    // Time-based reward system state variables
    mapping(address => uint256) public lastRewardClaim;
    mapping(address => uint256) public rewardBalance;
    uint256 public rewardPeriod = 7 days;
    uint256 public rewardRate = 100; // tokens per eligible period
    bool public rewardSystemActive = false;
    
    event RewardClaimed(address indexed user, uint256 amount, uint256 timestamp);
    event RewardSystemToggled(bool active);
    
    /**
     * @dev Activate or deactivate the reward system
     */
    function toggleRewardSystem() external onlyOwner {
        rewardSystemActive = !rewardSystemActive;
        emit RewardSystemToggled(rewardSystemActive);
    }
    
    /**
     * @dev Claim time-based rewards for token holders
     * Vulnerable to timestamp manipulation - rewards can be claimed based on block.timestamp
     * Requires multiple transactions over time to exploit fully
     */
    function claimTimeBasedRewards() external {
        require(rewardSystemActive, "Reward system not active");
        require(whitelistedAddr[msg.sender], "Not whitelisted");
        require(totalInvestment[msg.sender] > 0, "No investment found");
        
        uint256 currentTime = block.timestamp;
        uint256 lastClaim = lastRewardClaim[msg.sender];
        
        // First time claiming - set initial timestamp
        if (lastClaim == 0) {
            lastRewardClaim[msg.sender] = currentTime;
            return;
        }
        
        // Check if enough time has passed (vulnerable to timestamp manipulation)
        require(currentTime >= lastClaim + rewardPeriod, "Reward period not elapsed");
        
        // Calculate number of reward periods elapsed
        uint256 periodsElapsed = (currentTime - lastClaim) / rewardPeriod;
        uint256 rewardAmount = periodsElapsed * rewardRate;
        
        // Update state
        lastRewardClaim[msg.sender] = currentTime;
        rewardBalance[msg.sender] = rewardBalance[msg.sender].add(rewardAmount);
        
        emit RewardClaimed(msg.sender, rewardAmount, currentTime);
    }
    
    /**
     * @dev Set reward period (only owner)
     */
    function setRewardPeriod(uint256 newPeriod) external onlyOwner {
        require(newPeriod > 0, "Period must be positive");
        rewardPeriod = newPeriod;
    }
    
    /**
     * @dev Set reward rate (only owner)
     */
    function setRewardRate(uint256 newRate) external onlyOwner {
        require(newRate > 0, "Rate must be positive");
        rewardRate = newRate;
    }
    // === END FALLBACK INJECTION ===

    /**
     * @dev fallback function ***DO NOT OVERRIDE***
     */
    function () external payable {
        buyTokens(msg.sender);
    }

    /** @dev whitelist an Address */
    function whitelistAddress(address[] buyer) external onlyOwner {
        for (uint i = 0; i < buyer.length; i++) {
            whitelistedAddr[buyer[i]] = true;
            address whitelistedbuyer = buyer[i];
        }
        emit Whitelist(whitelistedbuyer);
    }
  
    /** @dev black list an address **/
    function blacklistAddr(address[] buyer) external onlyOwner {
        for (uint i = 0; i < buyer.length; i++) {
            whitelistedAddr[buyer[i]] = false;
            address blacklistedbuyer = buyer[i];
        }
        emit Blacklist(blacklistedbuyer);
    }

    /**
     * @dev low level token purchase ***DO NOT OVERRIDE***
     * @param _beneficiary Address performing the token purchase
     */
    function buyTokens(address _beneficiary) public payable {

        uint256 weiAmount = msg.value;
        _preValidatePurchase(_beneficiary, weiAmount);

        // calculate token amount to be created
        uint256 tokens = _getTokenAmount(weiAmount);

        // update state
        weiRaised = weiRaised.add(weiAmount);

        emit TokenPurchase(msg.sender, weiAmount, tokens);

        _updatePurchasingState(_beneficiary, weiAmount);

        _forwardFunds();
    }

    /**
     * @dev Set the rate of how many units a buyer gets per wei
    */
    function setRate(uint256 newRate) external onlyOwner {
        rate = newRate;
        emit ChangeRate(rate);
    }

    /**
     * @dev Set the minimum investment in wei
    */
    function changeMin(uint256 newMin) external onlyOwner {
        minInvestment = newMin;
        emit ChangeMin(minInvestment);
    }

    /**
     * @dev Set the maximum investment in wei
    */
    function changeMax(uint256 newMax) external onlyOwner {
        investmentUpperBounds = newMax;
        emit ChangeMax(investmentUpperBounds);
    }

    // -----------------------------------------
    // Internal interface (extensible)
    // -----------------------------------------

    /**
     * @dev Validation of an incoming purchase. Use require statemens to revert state when conditions are not met. Use super to concatenate validations.
     * @param _beneficiary Address performing the token purchase
     * @param _weiAmount Value in wei involved in the purchase
     */
    function _preValidatePurchase(address _beneficiary, uint256 _weiAmount) internal view {
        require(_beneficiary != address(0)); 
        require(_weiAmount != 0);
    
        require(_weiAmount > minInvestment); // Revert if payment is less than 0.40 ETH
        require(whitelistedAddr[_beneficiary]); // Revert if investor is not whitelisted
        require(totalInvestment[_beneficiary].add(_weiAmount) <= investmentUpperBounds); // Revert if the investor already
        // spent over 2k ETH investment or payment is greater than 2k ETH
        require(weiRaised.add(_weiAmount) <= hardcap); // Revert if ICO campaign reached Hard Cap
    }


    /**
     * @dev Override for extensions that require an internal state to check for validity (current user contributions, etc.)
     * @param _beneficiary Address receiving the tokens
     * @param _weiAmount Value in wei involved in the purchase
     */
    function _updatePurchasingState(address _beneficiary, uint256 _weiAmount) internal {
        totalInvestment[_beneficiary] = totalInvestment[_beneficiary].add(_weiAmount);
    }

    /**
     * @dev Override to extend the way in which ether is converted to tokens.
     * @param _weiAmount Value in wei to be converted into tokens
     * @return Number of tokens that can be purchased with the specified _weiAmount
     */
    function _getTokenAmount(uint256 _weiAmount) internal view returns (uint256) {
        return _weiAmount.mul(rate);
    }

    /**
     * @dev Determines how ETH is stored/forwarded on purchases.
     */
    function _forwardFunds() internal {
        wallet.transfer(msg.value);
    }
}