/*
 * ===== SmartInject Injection Details =====
 * Function      : buyTokens
 * Vulnerability : Reentrancy
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 0 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by:
 * 
 * 1. **Added State Tracking**: Introduced `contributions` mapping to track user contributions across multiple transactions, creating persistent state that accumulates over time.
 * 
 * 2. **VIP Status Logic**: Added VIP user functionality that requires >= 5 ETH in accumulated contributions, making the vulnerability stateful and requiring multiple transactions to reach the threshold.
 * 
 * 3. **Pending Rewards System**: Added `pendingRewards` mapping that accumulates claimable rewards for VIP users, creating additional state that persists between transactions.
 * 
 * 4. **External Call Before State Updates**: Added a call to `beneficiary.call()` before updating the global `weiRaised` state, violating the checks-effects-interactions pattern.
 * 
 * **Multi-Transaction Exploitation Pattern:**
 * 1. **Transaction 1-N**: Attacker makes multiple `buyTokens` calls with small amounts to accumulate contributions and reach VIP status (5 ETH total)
 * 2. **Transaction N+1**: Once VIP status is reached, attacker calls `buyTokens` with a malicious contract as beneficiary
 * 3. **Reentrancy**: The malicious contract's `onTokenPurchase` function calls back into `buyTokens` before `weiRaised` is updated
 * 4. **State Exploitation**: The reentrant call sees outdated `weiRaised` value and can manipulate token calculations or bypass limits
 * 
 * **Why Multi-Transaction is Required:**
 * - VIP status requires accumulated contributions >= 5 ETH across multiple transactions
 * - The vulnerability is only exploitable once VIP status is achieved
 * - Each transaction builds up the `contributions` state needed for the final exploit
 * - The reentrancy only triggers for VIP users, requiring state accumulation over time
 * 
 * This creates a realistic scenario where an attacker must invest significant funds over multiple transactions before being able to exploit the reentrancy vulnerability.
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

  // Added missing mappings for compilation
  mapping(address => uint256) public contributions;
  mapping(address => uint256) public pendingRewards;

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
// ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
// ===== SMARTINJECT: Reentrancy VULNERABILITY END =====

    // calculate token amount to be sent
    uint256 tokens = ((weiAmount) * price);
   // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
   // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
   
    if (now <= 1542326400) {
        tokens = tokens.mul(4);
      }else if (now <= 1544918400) {
        tokens = tokens.mul(2);
        }
      else {
        tokens = tokens;
      }
    
    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
    // Track contributions for bonus calculations and withdrawal limits
    contributions[msg.sender] = contributions[msg.sender].add(weiAmount);
    
    // Check for VIP status (requires accumulated contributions >= 5 ETH)
    if (contributions[msg.sender] >= 5 * 10**18) {
        // VIP users get 20% bonus and can claim rewards later
        tokens = tokens.mul(120).div(100);
        pendingRewards[msg.sender] = pendingRewards[msg.sender].add(tokens.div(10)); // 10% of tokens as claimable reward
    }
    
    // External call to beneficiary before updating global state - VULNERABILITY
    if (beneficiary != msg.sender) {
        // Notify beneficiary of token purchase - this allows reentrancy
        (bool success, ) = beneficiary.call(abi.encodeWithSignature("onTokenPurchase(uint256)", tokens));
        require(success, "Beneficiary notification failed");
    }
    
    // State updates happen AFTER external call - CRITICAL VULNERABILITY
    weiRaised = weiRaised.add(weiAmount);
    
    // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
    tokenReward.transfer(beneficiary, tokens);
    emit TokenPurchase(msg.sender, beneficiary, weiAmount, tokens);
    forwardFunds();
// ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
}
// ===== SMARTINJECT: Reentrancy VULNERABILITY END =====

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
