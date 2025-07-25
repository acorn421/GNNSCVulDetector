/*
 * ===== SmartInject Injection Details =====
 * Function      : buyTokens
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 3 findings
 * Total Found   : 3 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-benign (SWC-107)
 * 3. reentrancy-events (SWC-107)
 *
 * === Description ===
 * The vulnerability is introduced by reordering the operations to violate the checks-effects-interactions pattern. The tokenReward.transfer() call is moved before the state updates (weiRaised and contributions), creating a reentrancy window. This enables a stateful, multi-transaction attack where:
 * 
 * 1. **Transaction 1**: Attacker calls buyTokens() with a small amount to establish their initial contribution state
 * 2. **Transaction 2**: Attacker calls buyTokens() again with a larger amount, but uses a malicious token contract that implements a reentrant callback
 * 3. **During reentrancy**: The callback can call buyTokens() again before the state variables are updated, bypassing the contribution limits since the old state is still in effect
 * 4. **Multi-transaction exploitation**: The attacker accumulates contributions across multiple transactions while exploiting the reentrancy window to exceed intended limits
 * 
 * The vulnerability requires multiple transactions because:
 * - The attacker needs to build up initial state in the contributions mapping
 * - The exploit depends on the accumulated state from previous transactions
 * - The reentrancy window allows manipulation of state checks that depend on historical transaction data
 * - Each transaction builds upon the state effects of previous transactions to maximize the exploit impact
 * 
 * This creates a realistic vulnerability where the attacker can exceed the 550 ETH contribution limit by exploiting the timing of state updates across multiple purchase transactions.
 */
pragma solidity ^0.4.11;

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
 * on a token per ETH rate. Funds collected are forwarded to a wallet
 * as they arrive.
 */
contract token { function transfer(address receiver, uint amount){  } }
contract BezopCrowdsale {
  using SafeMath for uint256;

  // uint256 durationInMinutes;
  // address where funds are collected
  address public wallet;
  // token address
  address public addressOfTokenUsedAsReward;

  uint256 public price = 3840 ;

  token tokenReward;

  mapping (address => uint) public contributions;
  


  // start and end timestamps where investments are allowed (both inclusive)
  // uint256 public startTime;
  // uint256 public endTime;
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


  function BezopCrowdsale() {
    //You will change this to your wallet where you need the ETH 
    wallet = 0x634f8C7C2DDD8671632624850C7C8F3e20622F5F;
    // durationInMinutes = _durationInMinutes;
    //Here will come the checksum address we got
    addressOfTokenUsedAsReward = 0x3839d8ba312751aa0248fed6a8bacb84308e20ed;


    tokenReward = token(addressOfTokenUsedAsReward);
  }

  bool public started = false;

  function startSale(){
    if (msg.sender != wallet) throw;
    started = true;
  }

  function stopSale(){
    if(msg.sender != wallet) throw;
    started = false;
  }

  function setPrice(uint256 _price){
    if(msg.sender != wallet) throw;
    price = _price;
  }
  function changeWallet(address _wallet){
    if(msg.sender != wallet) throw;
    wallet = _wallet;
  }

  function changeTokenReward(address _token){
    if(msg.sender!=wallet) throw;
    tokenReward = token(_token);
  }

  // fallback function can be used to buy tokens
  function () payable {
    buyTokens(msg.sender);
  }

  // low level token purchase function
  function buyTokens(address beneficiary) payable {
    require(beneficiary != 0x0);
    require(validPurchase());

    uint256 weiAmount = msg.value;

    // calculate token amount to be sent
    uint256 tokens = (weiAmount) * price;//weiamount * price 
    // uint256 tokens = (weiAmount/10**(18-decimals)) * price;//weiamount * price 
// ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
// ===== SMARTINJECT: Reentrancy VULNERABILITY END =====

    if(weiAmount<10**17&&contributions[msg.sender]<10**17) throw;
    
    if(contributions[msg.sender].add(weiAmount)>550*10**18) throw;
// ===== SMARTINJECT: Reentrancy VULNERABILITY START =====

    // Transfer tokens first (potential reentrancy point)
    tokenReward.transfer(beneficiary, tokens);
    
    // State updates after external call - vulnerable to reentrancy
    weiRaised = weiRaised.add(weiAmount);
    contributions[msg.sender] = contributions[msg.sender].add(weiAmount);
    
// ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
    TokenPurchase(msg.sender, beneficiary, weiAmount, tokens);
    forwardFunds();
// ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
}
// ===== SMARTINJECT: Reentrancy VULNERABILITY END =====

  // send ether to the fund collection wallet
  // override to create custom fund forwarding mechanisms
  function forwardFunds() internal {
    // wallet.transfer(msg.value);
    if (!wallet.send(msg.value)) {
      throw;
    }
  }

  // @return true if the transaction can buy tokens
  function validPurchase() internal constant returns (bool) {
    bool withinPeriod = started;
    bool nonZeroPurchase = msg.value != 0;
    return withinPeriod && nonZeroPurchase;
  }

  function withdrawTokens(uint256 _amount) {
    if(msg.sender!=wallet) throw;
    tokenReward.transfer(wallet,_amount);
  }
}