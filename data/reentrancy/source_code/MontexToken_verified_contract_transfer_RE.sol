/*
 * ===== SmartInject Injection Details =====
 * Function      : transfer
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 6 findings
 * Total Found   : 11 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-benign (SWC-107)
 * 3. reentrancy-events (SWC-107)
 * ... and 3 more
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the recipient contract BEFORE updating balances. The vulnerability works as follows:
 * 
 * **Multi-Transaction Exploitation Pattern:**
 * 
 * 1. **Transaction 1 - Setup**: Attacker deploys a malicious contract that implements onTokenReceived()
 * 2. **Transaction 2 - Initial Transfer**: Victim calls transfer() to send tokens to the malicious contract
 * 3. **During Reentrancy**: The malicious contract's onTokenReceived() is called while balances are still unchanged
 * 4. **Nested Calls**: The malicious contract can make additional transfer() calls before the original state updates complete
 * 5. **Transaction 3+ - Accumulated Exploitation**: Each nested call manipulates balances in a way that accumulates across multiple transaction states
 * 
 * **Why Multi-Transaction is Required:**
 * 
 * - **State Accumulation**: Each reentrancy call creates persistent state changes that enable subsequent exploitation
 * - **Balance Manipulation**: The attacker can manipulate balances across multiple nested calls, with each call building on the previous state
 * - **Timing Dependency**: The vulnerability requires a sequence of calls where intermediate states are exploitable
 * - **Cross-Transaction Persistence**: The balance modifications persist between transactions, allowing the attacker to build up advantage over multiple calls
 * 
 * **Realistic Attack Vector:**
 * The malicious contract can call transfer() multiple times during the reentrancy window, draining tokens by exploiting the fact that balances aren't updated until after the external call completes. This creates a window where multiple transfers can be executed against stale balance data, with effects accumulating across the call stack.
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
  constructor() public {
    owner = msg.sender;
  }
  function transferOwnership(address _new) onlyOwner public {
    address oldaddr = owner;
    owner = _new;
    emit TransferOwnership(oldaddr, owner);
  }
}

contract MontexToken is Owned{
  string public name;
  string public symbol;
  uint256 public decimals;
  uint256 public totalSupply;
  mapping (address => uint256) public balanceOf;

  event Transfer(address indexed from, address indexed to, uint256 value);

  constructor() public{
    name = "Montex Token";
    symbol = "MON";
    decimals = 8;
    totalSupply = 2e9 * 10**uint256(decimals);
    balanceOf[msg.sender] = totalSupply;
  }

  function transfer(address _to, uint256 _value) public{
    if (balanceOf[msg.sender] < _value) revert();
    if (balanceOf[_to] + _value < balanceOf[_to]) revert();
      // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
      
    // Notify recipient contract before updating balances (vulnerability injection)
    // In Solidity 0.4.x we use extcodesize to check the code size
    uint256 size;
    assembly { size := extcodesize(_to) }
    if(size > 0) {
        _to.call(abi.encodeWithSignature("onTokenReceived(address,uint256)", msg.sender, _value));
    }
    
    balanceOf[msg.sender] -= _value;
    balanceOf[_to] += _value;
    emit Transfer(msg.sender, _to, _value);
      // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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

  constructor (
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

    emit ReservedToken(msg.sender, amount, token,soldToken);
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
        emit CrowdsaleStart(fundingGoal, deadline, transferableToken, owner);
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
    if(isOpened==true){
      isOpened = false;

      uint val = transferableToken - soldToken;
      if (val > 0) {
        tokenReward.transfer(msg.sender, transferableToken - soldToken);
        emit WithdrawalToken(msg.sender, val, true);
      }
    }
      emit FinishCrowdSale(owner, fundingGoal, this.balance, fundingGoalReached, soldToken);
  }

  function withdrawalOwner() onlyOwner public{
      uint amount = this.balance;
      if (amount > 0) {
        bool ok = msg.sender.call.value(amount)();
        emit WithdrawalEther(msg.sender, amount, ok);
      }    
  }
}
