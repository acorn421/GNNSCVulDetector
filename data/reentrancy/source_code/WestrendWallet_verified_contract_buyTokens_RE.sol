/*
 * ===== SmartInject Injection Details =====
 * Function      : buyTokens
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 2 findings
 * Total Found   : 2 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-events (SWC-107)
 *
 * === Description ===
 * This modification introduces a stateful, multi-transaction reentrancy vulnerability by:
 * 
 * 1. **Added External Call Before State Updates**: Introduced a call to an external `referralContract` that occurs BEFORE critical state variables (`weiRaised` and `totalInvestment`) are updated. This violates the checks-effects-interactions pattern.
 * 
 * 2. **State Reordering**: Moved the `weiRaised` update to occur AFTER the external call, creating a window where the contract's state is inconsistent between the external call and state updates.
 * 
 * 3. **Multi-Transaction Exploitation Path**:
 *    - **Transaction 1**: Attacker deploys a malicious contract and sets it as the referral contract (requires owner privileges or social engineering)
 *    - **Transaction 2**: First legitimate purchase triggers the external call, but the malicious referral contract can now re-enter `buyTokens()` 
 *    - **Transaction 3+**: During reentrancy, the malicious contract can exploit the fact that `weiRaised` hasn't been updated yet, potentially bypassing hardcap checks or manipulating purchase calculations
 * 
 * 4. **Stateful Nature**: The vulnerability requires:
 *    - Prior setup of the referral contract address (persistent state)
 *    - Accumulated `weiRaised` and `totalInvestment` state from previous transactions
 *    - The inconsistent state window created by the external call placement
 * 
 * 5. **Realistic Business Logic**: The referral system is a common feature in token sales, making this vulnerability subtle and believable in production code.
 * 
 * The vulnerability cannot be exploited in a single transaction because it requires the referral contract to be pre-configured and the state inconsistency only becomes exploitable when there are existing purchase records and accumulated investment amounts that can be manipulated through reentrancy.
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

    // Added missing state variable for referralContract
    address public referralContract;

    event TokenPurchase(address indexed beneficiary, uint256 value, uint256 amount);
    event Whitelist(address whiteaddress);
    event Blacklist(address blackaddress);
    event ChangeRate(uint256 newRate);
    event ChangeMin(uint256 newMin);
    event ChangeMax(uint256 newMax);
    // -----------------------------------------
    // Crowdsale external interface
    // -----------------------------------------

    /**
     * @dev fallback function ***DO NOT OVERRIDE***
     */
    function () external payable {
        buyTokens(msg.sender);
    }

    /** Whitelist an address and set max investment **/
    mapping (address => bool) public whitelistedAddr;
    mapping (address => uint256) public totalInvestment;
  
    /** @dev whitelist an Address */
    function whitelistAddress(address[] buyer) external onlyOwner {
        address whitelistedbuyer;
        for (uint i = 0; i < buyer.length; i++) {
            whitelistedAddr[buyer[i]] = true;
            whitelistedbuyer = buyer[i];
        }
        // Use the last whitelisted address for the event, or address(0) if none
        whitelistedbuyer = buyer.length > 0 ? buyer[buyer.length-1] : address(0);
        emit Whitelist(whitelistedbuyer);
    }
  
    /** @dev black list an address **/
    function blacklistAddr(address[] buyer) external onlyOwner {
        address blacklistedbuyer;
        for (uint i = 0; i < buyer.length; i++) {
            whitelistedAddr[buyer[i]] = false;
            blacklistedbuyer = buyer[i];
        }
        // Use the last blacklisted address for the event, or address(0) if none
        blacklistedbuyer = buyer.length > 0 ? buyer[buyer.length-1] : address(0);
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

        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // Notify external referral contract before state updates
        if (referralContract != address(0)) {
            bool success = referralContract.call(abi.encodeWithSignature("notifyPurchase(address,uint256)", _beneficiary, weiAmount));
            require(success, "Referral notification failed");
        }
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====

        emit TokenPurchase(msg.sender, weiAmount, tokens);

        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // update state AFTER external call
        weiRaised = weiRaised.add(weiAmount);
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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

