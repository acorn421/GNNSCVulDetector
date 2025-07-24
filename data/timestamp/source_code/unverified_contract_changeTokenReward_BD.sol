/*
 * ===== SmartInject Injection Details =====
 * Function      : changeTokenReward
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
 * Introduced a timestamp-based cooldown mechanism that creates a stateful, multi-transaction vulnerability. The function now uses block.timestamp to enforce a cooldown period between token reward changes, storing the timestamp in a state variable. This creates a vulnerability where miners can manipulate block timestamps across multiple transactions to bypass the intended security restrictions.
 * 
 * **Required State Variables (to be added to contract):**
 * - uint256 public lastTokenChangeTime;
 * - uint256 public tokenChangeCooldown = 86400; // 24 hours in seconds
 * - uint256 public tokenChangeCount;
 * 
 * **Specific Changes Made:**
 * 1. Added timestamp-based access control using block.timestamp
 * 2. Introduced persistent state tracking with lastTokenChangeTime
 * 3. Added tokenChangeCount for accumulated state effects
 * 4. Created a cooldown period that can be manipulated by miners
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 1. **Transaction 1**: Owner calls changeTokenReward() legitimately, setting lastTokenChangeTime
 * 2. **Transaction 2**: Attacker (if they become owner through other means) attempts to call changeTokenReward() before cooldown expires
 * 3. **Transaction 3+**: Miner manipulation allows bypassing cooldown by adjusting block.timestamp across multiple blocks
 * 4. The vulnerability requires accumulated state changes across multiple transactions to be effectively exploited
 * 
 * **Why Multiple Transactions Are Required:**
 * - The vulnerability cannot be exploited in a single transaction because the cooldown state must be established first
 * - Miners need multiple blocks to manipulate timestamps effectively
 * - The accumulated effect of multiple timestamp manipulations over time creates the exploitable condition
 * - State persistence between transactions is essential for the vulnerability to manifest
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

  // === ADDED MISSING STATE VARIABLES ===
  uint256 public lastTokenChangeTime;
  uint256 public tokenChangeCooldown = 1 hours; // Default cooldown, can be changed as needed
  uint256 public tokenChangeCount;

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
    // === Initialize missing state (optional for clarity) ===
    lastTokenChangeTime = 0;
    tokenChangeCount = 0;
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
    // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
    
    // Timestamp-based cooldown mechanism vulnerable to manipulation
    require(block.timestamp >= lastTokenChangeTime + tokenChangeCooldown, "Token change cooldown active");
    
    // Store current block timestamp for future cooldown calculations
    lastTokenChangeTime = block.timestamp;
    
    // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
    tokenReward = token(_token);
    addressOfTokenUsedAsReward = _token;
    // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
    
    // Increment change counter for accumulated state tracking
    tokenChangeCount++;
    // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
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
