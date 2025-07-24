/*
 * ===== SmartInject Injection Details =====
 * Function      : changeTokenReward
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 2 findings
 * Total Found   : 4 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-benign (SWC-107)
 *
 * === Description ===
 * This modification introduces a stateful, multi-transaction reentrancy vulnerability by:
 * 
 * 1. **Added External Calls Before State Updates**: The function now makes external calls to the old token contract (transfer) and new token contract (balanceOf) before completing all state updates, violating the checks-effects-interactions pattern.
 * 
 * 2. **State Inconsistency Window**: Between the external calls, the contract is in an inconsistent state where tokenReward is updated but addressOfTokenUsedAsReward still points to the old token.
 * 
 * 3. **Multi-Transaction Exploitation**:
 *    - **Transaction 1**: Attacker calls changeTokenReward with a malicious token contract
 *    - **During Transaction 1**: The malicious token's balanceOf function re-enters the contract, finding tokenReward updated but addressOfTokenUsedAsReward still pointing to old token
 *    - **Transaction 2**: Attacker exploits this inconsistent state by calling other contract functions that rely on these state variables
 *    - **Transaction 3**: Complete exploitation using the persisted state changes
 * 
 * 4. **Stateful Nature**: The vulnerability relies on the persistent state changes to tokenReward and addressOfTokenUsedAsReward that affect subsequent transactions and function calls.
 * 
 * 5. **Realistic Attack Vector**: A malicious token contract can implement transfer() or balanceOf() to re-enter the crowdsale contract during the state transition, exploiting the inconsistent state where critical variables are misaligned.
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


  constructor() public {
    //You will change this to your wallet where you need the ETH 
    wallet = 0xAe2544ec9F7716998d102fcdCa9CC401B3277203;
    // durationInMinutes = _durationInMinutes;
    //Here will come the checksum address we got
    addressOfTokenUsedAsReward = 0x16c86d6e140e0cD7F9a993C3f1632A4c3A0af008;


    tokenReward = token(addressOfTokenUsedAsReward);
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
    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
    
    // External call to validate token before updating state
    // This creates a reentrancy window where state is partially updated
    if(addressOfTokenUsedAsReward != address(0)) {
        // Notify the old token contract about the change
        // This external call happens before state is fully updated
        token(addressOfTokenUsedAsReward).transfer(address(this), 0);
    }
    
    // State update happens after external call - vulnerable to reentrancy
    tokenReward = token(_token);
    
    // Another external call before completing state updates
    // Check if new token contract is valid by calling balanceOf
    uint256 balance = token(_token).balanceOf(address(this));
    
    // Final state update after external calls
    // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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