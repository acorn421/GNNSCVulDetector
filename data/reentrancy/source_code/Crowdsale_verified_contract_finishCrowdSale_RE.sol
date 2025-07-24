/*
 * ===== SmartInject Injection Details =====
 * Function      : finishCrowdSale
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 2 findings
 * Total Found   : 9 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Modified the finishCrowdSale function to introduce a stateful, multi-transaction reentrancy vulnerability by moving the critical state update `isOpened = false` to occur AFTER the external token transfer call. This creates a vulnerability window where:
 * 
 * **Multi-Transaction Exploitation Process:**
 * 
 * 1. **Transaction 1 (Initial Setup)**: Owner calls finishCrowdSale() which triggers tokenReward.transfer() but before isOpened is set to false, the transfer can re-enter
 * 
 * 2. **Transaction 2+ (Reentrancy Chain)**: During the token transfer, if the tokenReward contract is malicious or compromised, it can call back into finishCrowdSale() while isOpened is still true, allowing multiple withdrawals of remaining tokens
 * 
 * **Why Multi-Transaction is Required:**
 * 
 * - **State Persistence**: The vulnerability depends on the persistent state of `isOpened` remaining true across multiple calls
 * - **Accumulated Effect**: Each reentrant call withdraws more tokens before the crowdsale is properly closed
 * - **Cross-Transaction Dependencies**: The attack requires establishing the initial state in one transaction, then exploiting the reentrancy window in subsequent calls triggered by the external transfer
 * 
 * **Key Vulnerability Points:**
 * 
 * 1. **Checks-Effects-Interactions Violation**: The function now checks conditions, makes external calls, then updates state
 * 2. **Stateful Reentrancy**: The `isOpened` state variable controls access and isn't updated until after the external call
 * 3. **Multi-Call Exploitation**: Attacker can drain remaining tokens through multiple reentrant calls before `isOpened` is set to false
 * 4. **Persistent State Window**: The vulnerability window persists across multiple function invocations due to delayed state updates
 * 
 * This creates a realistic production-level vulnerability that requires multiple transactions to fully exploit and depends on accumulated state changes between calls.
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

  function finishCrowdSale() onlyOwner public {
    if (this.balance >= fundingGoal) {
      fundingGoalReached = true;
    }
    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
    // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
    if(isOpened==true){
      uint val = transferableToken - soldToken;
      if (val > 0) {
        tokenReward.transfer(msg.sender, transferableToken - soldToken);
        WithdrawalToken(msg.sender, val, true);
      }
      // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
      
      // State update moved after external call - creates reentrancy window
      isOpened = false;
      // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
    }
      FinishCrowdSale(owner, fundingGoal, this.balance, fundingGoalReached, soldToken);
  }

  function withdrawalOwner() onlyOwner public{
      uint amount = this.balance;
      if (amount > 0) {
        bool ok = msg.sender.call.value(amount)();
        WithdrawalEther(msg.sender, amount, ok);
      }    
  }
}