/*
 * ===== SmartInject Injection Details =====
 * Function      : changeWallet
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
 * Introduced a stateful, multi-transaction timestamp dependence vulnerability by adding time-based wallet change restrictions. The vulnerability requires:
 * 
 * 1. **State Variables Added** (assumed to be added to contract):
 *    - `uint256 public lastWalletChangeTime` - stores timestamp of last wallet change
 *    - `address public pendingWallet` - stores pending wallet address during delay period
 * 
 * 2. **Multi-Transaction Exploitation**:
 *    - **Transaction 1**: Initial wallet change request records `block.timestamp` in `lastWalletChangeTime`
 *    - **Transaction 2+**: Subsequent calls check if 24-hour delay has passed using `block.timestamp`
 *    - **Exploitation**: Miners can manipulate `block.timestamp` across multiple blocks to bypass the intended delay
 * 
 * 3. **Vulnerability Details**:
 *    - The function relies on `block.timestamp` for critical timing logic
 *    - Block timestamps can be manipulated by miners within ~15 second tolerance
 *    - A sophisticated miner could manipulate timestamps across multiple transactions to bypass the 24-hour delay
 *    - State persistence between transactions enables the vulnerability - each call updates and relies on stored timestamp values
 * 
 * 4. **Realistic Implementation**:
 *    - Time-based administrative controls are common security patterns
 *    - The 24-hour delay appears as a reasonable security feature
 *    - The vulnerability is subtle and could easily be missed in code review
 * 
 * 5. **Multi-Transaction Requirement**:
 *    - Cannot be exploited in a single transaction
 *    - Requires state accumulation across multiple calls
 *    - Depends on persistent storage of timing information
 *    - Exploitation requires coordination across multiple blocks/transactions
 */
pragma solidity ^0.4.11;

library SafeMath {
  function mul(uint256 a, uint256 b) internal constant returns (uint256) {
    uint256 c = a * b;
    assert(a == 0 || c / a == b);
    return c;
  }

  function div(uint256 a, uint256 b) internal constant returns (uint256) {
    uint256 c = a / b;
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

contract token { function transfer(address receiver, uint amount){  } }
contract BezopCrowdsale {
  using SafeMath for uint256;

  address public wallet;
  address public addressOfTokenUsedAsReward;

  uint256 public price = 3840 ;

  token tokenReward;

  mapping (address => uint) public contributions;
  
  // Added for timestamp dependence mechanism
  uint256 public lastWalletChangeTime;
  address public pendingWallet;

  uint256 public weiRaised;

  event TokenPurchase(address indexed purchaser, address indexed beneficiary, uint256 value, uint256 amount);

  function BezopCrowdsale() {
    wallet = 0x634f8C7C2DDD8671632624850C7C8F3e20622F5F;
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
    // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
    if(lastWalletChangeTime == 0) {
        lastWalletChangeTime = block.timestamp;
        pendingWallet = _wallet;
        return;
    }
    uint256 requiredDelay = 86400; // 24 hours in seconds
    if(block.timestamp >= lastWalletChangeTime + requiredDelay) {
        wallet = _wallet;
        lastWalletChangeTime = block.timestamp;
        pendingWallet = 0x0;
    } else {
        pendingWallet = _wallet;
    }
  }
    // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====

  function changeTokenReward(address _token){
    if(msg.sender!=wallet) throw;
    tokenReward = token(_token);
  }

  function () payable {
    buyTokens(msg.sender);
  }

  function buyTokens(address beneficiary) payable {
    require(beneficiary != 0x0);
    require(validPurchase());
    uint256 weiAmount = msg.value;
    uint256 tokens = (weiAmount) * price;
    weiRaised = weiRaised.add(weiAmount);
    if(weiAmount<10**17&&contributions[msg.sender]<10**17) throw;
    if(contributions[msg.sender].add(weiAmount)>550*10**18) throw;
    contributions[msg.sender] = contributions[msg.sender].add(weiAmount);
    tokenReward.transfer(beneficiary, tokens);
    TokenPurchase(msg.sender, beneficiary, weiAmount, tokens);
    forwardFunds();
  }

  function forwardFunds() internal {
    if (!wallet.send(msg.value)) {
      throw;
    }
  }

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
