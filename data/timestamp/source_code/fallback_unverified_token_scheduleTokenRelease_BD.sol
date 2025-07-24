/*
 * ===== SmartInject Injection Details =====
 * Function      : scheduleTokenRelease
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 4 issues
 * Retry Count   : 0
 *
 * === Description ===
 * This vulnerability introduces timestamp dependence through a multi-transaction token release mechanism. The vulnerability requires multiple transactions to exploit: first calling scheduleTokenRelease() to set a release time, then calling releaseLockedTokens() which depends on block.timestamp. Miners can manipulate the timestamp to release tokens earlier than intended or delay releases. The state persists between transactions through the lockedTokens and releaseTime mappings, making this a stateful vulnerability that cannot be exploited in a single transaction.
 */
pragma solidity ^0.4.24;

/**
 * @title SafeMath
 * @dev Math operations with safety checks that throw on error
 */
library SafeMath {
  function mul(uint256 a, uint256 b) internal constant returns (uint256) {
    uint256 c = a * b;
    assert(a == 0 || c / a == b);
    return c;
  }

  function div(uint256 a, uint256 b) internal constant returns (uint256) {
    // assert(b > 0); // Solidity automatically throws when dividing by 0 uint256 c = a / b;
    uint256 c = a / b;
    // assert(a == b * c + a % b); // There is no case in which this doesn't hold
    return c;
  }

  function sub(uint256 a, uint256 b) internal constant returns (uint256) {
    assert(b <= a);
    return a - b;
  }

  function add(uint256 a, uint256 b) internal constant returns (uint256) {
    uint256 c = a + b;
    assert(c >= a);
    return c;
  }
}

/**
 * @title Crowdsale
 * @dev Crowdsale is a base contract for managing a token crowdsale.
 * Crowdsales have a start and end timestamps, where investors can make
 * token purchases and the crowdsale will assign them tokens based
 * on a token per ETH rate. Funds collected are forwarded 
 to a wallet
 * as they arrive.
 */
contract token { function transfer(address receiver, uint amount) public{  }
    function balanceOf(address _owner) public returns (uint256 balance){ }
}
contract IMCrowdsale {
  using SafeMath for uint256;

  // uint256 durationInMinutes;
  // address where funds are collected
  address public wallet;
  // token address
  address public addressOfTokenUsedAsReward;

  uint256 public price = 500;

  token tokenReward;

  // amount of raised money in wei
  uint256 public weiRaised;

  /**
   * event for token purchase logging
   * @param purchaser who paid for the tokens
   * @param beneficiary who got the tokens
   * @param value weis paid for purchase
   * @param amount amount of tokens purchased
   */
  event TokenPurchase(address indexed purchaser, address indexed beneficiary, uint256 value, uint256 amount);

  // Mappings for lockup functionality
  mapping(address => uint256) public lockedTokens;
  mapping(address => uint256) public releaseTime;

  constructor() public {
    //You will change this to your wallet where you need the ETH 
    wallet = 0xAe2544ec9F7716998d102fcdCa9CC401B3277203;
    // durationInMinutes = _durationInMinutes;
    //Here will come the checksum address we got
    addressOfTokenUsedAsReward = 0x16c86d6e140e0cD7F9a993C3f1632A4c3A0af008;

    tokenReward = token(addressOfTokenUsedAsReward);
  }

  /**
   * @dev Schedule tokens to be released at a specific time
   * @param beneficiary Address to receive the tokens
   * @param amount Amount of tokens to lock
   * @param _releaseTime Timestamp when tokens can be released
   */
  function scheduleTokenRelease(address beneficiary, uint256 amount, uint256 _releaseTime) external {
      if(msg.sender != wallet) revert();
      require(beneficiary != 0x0);
      require(amount > 0);
      require(_releaseTime > now);
      lockedTokens[beneficiary] = lockedTokens[beneficiary].add(amount);
      releaseTime[beneficiary] = _releaseTime;
      // Transfer tokens to contract for holding
      tokenReward.transfer(address(this), amount);
  }

  /**
   * @dev Release locked tokens if current time is past release time
   * @param beneficiary Address to release tokens for
   */
  function releaseLockedTokens(address beneficiary) external {
      require(beneficiary != 0x0);
      require(lockedTokens[beneficiary] > 0);
      // VULNERABILITY: Timestamp dependence - miners can manipulate block.timestamp
      if(now >= releaseTime[beneficiary]) {
          uint256 amount = lockedTokens[beneficiary];
          lockedTokens[beneficiary] = 0;
          releaseTime[beneficiary] = 0;
          tokenReward.transfer(beneficiary, amount);
      }
  }

  /**
   * @dev Emergency function to extend release time (vulnerable to timestamp manipulation)
   * @param beneficiary Address to extend release time for
   * @param additionalTime Additional time to add to release time
   */
  function extendReleaseTime(address beneficiary, uint256 additionalTime) external {
      if(msg.sender != wallet) revert();
      require(beneficiary != 0x0);
      require(lockedTokens[beneficiary] > 0);
      // VULNERABILITY: Timestamp dependence in state modification
      releaseTime[beneficiary] = now + additionalTime;
  }

  bool public started = true;

  function startSale() external{
    if (msg.sender != wallet) revert();
    started = true;
  }

  function stopSale() external{
    if(msg.sender != wallet) revert();
    started = false;
  }

  function setPrice(uint256 _price) external{
    if(msg.sender != wallet) revert();
    price = _price;
  }
  function changeWallet(address _wallet) external{
      if(msg.sender != wallet) revert();
      wallet = _wallet;
  }

  function changeTokenReward(address _token) external{
    if(msg.sender!=wallet) revert();
    tokenReward = token(_token);
    addressOfTokenUsedAsReward = _token;
  }

  // fallback function can be used to buy tokens
  function () payable public {
    buyTokens(msg.sender);
  }

  // low level token purchase function
  function buyTokens(address beneficiary) payable public {
    require(beneficiary != 0x0);
    require(validPurchase());
    uint256 weiAmount = msg.value;
    // calculate token amount to be sent
    uint256 tokens = ((weiAmount) * price);
    weiRaised = weiRaised.add(weiAmount);
    if (now <= 1542326400) {
        tokens = tokens.mul(4);
      }else if (now <= 1544918400) {
        tokens = tokens.mul(2);
        }
      else {
        tokens = tokens;
      }
    // if(contributions[msg.sender].add(weiAmount)>10*10**18) throw;
    // contributions[msg.sender] = contributions[msg.sender].add(weiAmount);
    tokenReward.transfer(beneficiary, tokens);
    emit TokenPurchase(msg.sender, beneficiary, weiAmount, tokens);
    forwardFunds();
  }

  // send ether to the fund collection wallet
  // override to create custom fund forwarding mechanisms
  function forwardFunds() internal {
    // wallet.transfer(msg.value);
    if (!wallet.send(msg.value)) {
      revert();
    }
  }

  // @return true if the transaction can buy tokens
  function validPurchase() internal constant returns (bool) {
    bool withinPeriod = started;
    bool nonZeroPurchase = msg.value != 0;
    return withinPeriod && nonZeroPurchase;
  }

  function withdrawTokens(uint256 _amount) external {
    if(msg.sender!=wallet) revert();
    tokenReward.transfer(wallet,_amount);
  }
  function destroy()  external {
    if(msg.sender != wallet) revert();
    // Transfer tokens back to owner
    uint256 balance = tokenReward.balanceOf(address(this));
    assert(balance > 0);
    tokenReward.transfer(wallet, balance);
    // There should be no ether in the contract but just in case
     selfdestruct(wallet);
  }

}
