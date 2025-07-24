/*
 * ===== SmartInject Injection Details =====
 * Function      : finishCrowdSale
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 10 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Introduced a multi-transaction timestamp dependence vulnerability by implementing a two-phase finalization process:
 * 
 * **Changes Made:**
 * 1. Added state variables: `finalizationStartTime`, `fundingGoalAtFinalization`, and `finalizationInProgress`
 * 2. Modified function to require two separate calls - first to start finalization, second to complete it
 * 3. Added timestamp-based logic using `block.timestamp` for critical funding goal determination
 * 4. Created a 1-hour vulnerable time window where different funding goal logic applies
 * 
 * **Multi-Transaction Exploitation:**
 * 1. **Transaction 1**: Owner calls `finishCrowdSale()` to start finalization, recording `block.timestamp` and current balance
 * 2. **Transaction 2**: After manipulating timestamp within the 1-hour window, owner calls again to complete finalization
 * 
 * **Why Multiple Transactions Required:**
 * - The vulnerability requires state persistence between calls (`finalizationStartTime`, `fundingGoalAtFinalization`)
 * - First transaction establishes the baseline timestamp and balance that subsequent calls depend on
 * - Miners/attackers need time between transactions to manipulate `block.timestamp` values
 * - The time window check (`block.timestamp >= finalizationStartTime + 3600`) creates dependency on accumulated timestamp differences across multiple blocks
 * - Single transaction exploitation is impossible because the timestamp manipulation requires mining multiple blocks with controlled timestamps
 * 
 * **Exploitation Scenario:**
 * A malicious miner could manipulate `block.timestamp` values across multiple transactions to either extend or compress the perceived time window, potentially allowing funding goal achievement even when the actual balance is insufficient, or preventing legitimate goal achievement by manipulating the timestamp comparisons.
 */
pragma solidity ^0.4.19;

library SafeMath {
  function mul(uint256 a, uint256 b) internal pure returns (uint256) {
    uint256 c = a * b;
    assert(a == 0 || c / a == b);
    return c;
  }

  function div(uint256 a, uint256 b) internal pure returns (uint256) {
    uint256 c = a / b;
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
contract Owned {
  address public owner;
  event TransferOwnership(address oldaddr, address newaddr);
  modifier onlyOwner() {
        require(msg.sender == owner);
    _;}
  function Owned() public {
    owner = msg.sender;
  }
  function transferOwnership(address _new) onlyOwner public {
    address oldaddr = owner;
    owner = _new;
    TransferOwnership(oldaddr, owner);
  }
}

contract MontexToken is Owned{
  string public name;
  string public symbol;
  uint256 public decimals;
  uint256 public totalSupply;
  mapping (address => uint256) public balanceOf;

  event Transfer(address indexed from, address indexed to, uint256 value);

  function MontexToken() public{
    name = "Montex Token";
    symbol = "MON";
    decimals = 8;
    totalSupply = 2e9 * 10**uint256(decimals);
    balanceOf[msg.sender] = totalSupply;
  }

  function transfer(address _to, uint256 _value) public{
    if (balanceOf[msg.sender] < _value) revert();
    if (balanceOf[_to] + _value < balanceOf[_to]) revert();
      balanceOf[msg.sender] -= _value;
      balanceOf[_to] += _value;
      Transfer(msg.sender, _to, _value);
  }
}

contract Crowdsale is Owned {
  using SafeMath for uint256;
  uint256 public fundingGoal;
  uint256 public price;
  uint256 public transferableToken;
  uint256 public soldToken;
  uint256 public deadline;
  uint256 public token_price;
  MontexToken public tokenReward;
  bool public fundingGoalReached = false;
  bool public isOpened;
  mapping (address => Property) public fundersProperty;

  struct Property {
    uint256 paymentEther;
    uint256 reservedToken;
  }

  event CrowdsaleStart(uint fundingGoal, uint deadline, uint transferableToken, address beneficiary);
  event ReservedToken(address backer, uint amount, uint token, uint soldToken);
  event WithdrawalToken(address addr, uint amount, bool result);
  event WithdrawalEther(address addr, uint amount, bool result);
  event FinishCrowdSale(address beneficiary, uint fundingGoal, uint amountRaised, bool reached, uint raisedToken);

  modifier afterDeadline() { if (now >= deadline) _; }

  function Crowdsale (
    uint _fundingGoalInEthers,
    uint _transferableToken,
    uint _amountOfTokenPerEther,
    MontexToken _addressOfTokenUsedAsReward
  ) public {
    fundingGoal = _fundingGoalInEthers * 1 ether;
    price = 1 ether / _amountOfTokenPerEther;
    tokenReward = MontexToken(_addressOfTokenUsedAsReward);
    transferableToken = _transferableToken * 10 ** uint256(8);
  }

  function () payable external{
    if (!isOpened || now >= deadline) revert();

    uint amount = msg.value;

    uint amont_conv = amount * 1000;
    uint token = (amont_conv / price * token_price / 1000) * 10 ** uint256(8);

    if (token == 0 || soldToken + token > transferableToken) revert();
    fundersProperty[msg.sender].paymentEther += amount / 10 ** uint256(8);
    fundersProperty[msg.sender].reservedToken += token;
    soldToken += token;

    tokenReward.transfer(msg.sender, token);

    ReservedToken(msg.sender, amount, token,soldToken);
  }

  function start(uint startTime,uint _deadline,uint _token_price) onlyOwner public{
    deadline = _deadline;
    token_price = _token_price;
    if (fundingGoal == 0 || transferableToken == 0 ||
        tokenReward == address(0) ||  startTime >= now)
    {
      revert();
    }
    if (tokenReward.balanceOf(this) >= transferableToken) {
      if(startTime <= now && now <= deadline){
        isOpened = true;
        CrowdsaleStart(fundingGoal, deadline, transferableToken, owner);
      }
    }
  }

  function getBalance(address _addres) public
  constant returns(uint nowpaymentEther,uint nowbuyToken)
  {
    nowpaymentEther = fundersProperty[_addres].paymentEther * (1 ether) / 10 ** uint256(8);
    nowbuyToken = fundersProperty[_addres].reservedToken;

  }  
  function valNowRate(uint _amount) public
    view returns(uint get_rate,uint get_token)
    {
    get_rate = token_price;
    get_token = _amount * get_rate;
  }


  function getRemainingTimeEthToken() public
    constant returns(
        uint now_time,
        uint now_deadline,
        uint remain_days,
        uint remain_hours,
        uint remain_minutes,
        uint remainEth,
        uint remainToken,
        uint remain_seconds,
        uint getEth,
        uint tokenReward_balance,
        uint transferable_token)
  {
    if(now < deadline) {
      remain_days = (deadline - now) / (1 days);
      remain_hours = (deadline - now) / (1 hours);
      remain_minutes = (deadline - now) / (1 minutes);
      remain_seconds = (deadline - now) / (1 seconds);
      now_time = now;
      now_deadline = deadline;
      
    }
    remainEth = (fundingGoal - this.balance) / (1 ether);
    remainToken = transferableToken - soldToken;
    getEth = this.balance / (1 ether);
    tokenReward_balance = tokenReward.balanceOf(this);
    transferable_token = transferableToken;
  }

  // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
uint256 public finalizationStartTime;
  uint256 public fundingGoalAtFinalization;
  bool public finalizationInProgress = false;

  function finishCrowdSale() onlyOwner public {
    // Start finalization process - record timestamp and current balance
    if (!finalizationInProgress) {
      finalizationStartTime = block.timestamp;
      fundingGoalAtFinalization = this.balance;
      finalizationInProgress = true;
      return;
    }
    
    // Allow funding goal achievement if sufficient time has passed since finalization start
    // This creates a time window where miners can manipulate timestamps
    if (block.timestamp >= finalizationStartTime + 3600) { // 1 hour window
      if (fundingGoalAtFinalization >= fundingGoal || this.balance >= fundingGoal) {
        fundingGoalReached = true;
      }
    } else {
      // Within the vulnerable time window, use stored balance for goal determination
      if (fundingGoalAtFinalization >= fundingGoal) {
        fundingGoalReached = true;
      }
    }
    
// ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
    if(isOpened==true){
      isOpened = false;

      uint val = transferableToken - soldToken;
      if (val > 0) {
        tokenReward.transfer(msg.sender, transferableToken - soldToken);
        WithdrawalToken(msg.sender, val, true);
      }
    }
    // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
    
    // Reset finalization state for potential future use
    finalizationInProgress = false;
    FinishCrowdSale(owner, fundingGoal, this.balance, fundingGoalReached, soldToken);
    // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
  }

  function withdrawalOwner() onlyOwner public{
      uint amount = this.balance;
      if (amount > 0) {
        bool ok = msg.sender.call.value(amount)();
        WithdrawalEther(msg.sender, amount, ok);
      }    
  }
}