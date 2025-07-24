/*
 * ===== SmartInject Injection Details =====
 * Function      : withdraw
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 1 findings
 * Total Found   : 3 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-eth (SWC-107)
 *
 * === Description ===
 * This introduces a stateful, multi-transaction reentrancy vulnerability. The attack requires: 1) First calling requestWithdraw() to set up the withdrawal request state, 2) Waiting for the time delay to pass, 3) Calling withdraw() which makes an external call before updating state, allowing for reentrancy attacks. The vulnerability is stateful because it depends on the withdrawRequests and withdrawTimestamps mappings persisting between transactions, and multi-transaction because it requires at least two separate transactions (request + withdraw) to exploit.
 */
pragma solidity ^0.4.24;

/**
 * SmartEth.co
 * ERC20 Token and ICO smart contracts development, smart contracts audit, ICO websites.
 * contact@smarteth.co
 */

/**
 * @title SafeMath
 */
library SafeMath {

  function mul(uint256 a, uint256 b) internal pure returns (uint256) {
    if (a == 0) {
      return 0;
    }
    uint256 c = a * b;
    assert(c / a == b);
    return c;
  }

  function div(uint256 a, uint256 b) internal pure returns (uint256) {
    // assert(b > 0); // Solidity automatically throws when dividing by 0
    uint256 c = a / b;
    // assert(a == b * c + a % b); // There is no case in which this doesn't hold
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

/**
 * @title ERC20Basic
 */
contract ERC20Basic {
  function totalSupply() public view returns (uint256);
  function balanceOf(address who) public view returns (uint256);
  function transfer(address to, uint256 value) public returns (bool);
  event Transfer(address indexed from, address indexed to, uint256 value);
}

/**
 * @title Bitway Coin
 */
contract BTW_Token is ERC20Basic {
  using SafeMath for uint256;

  mapping(address => uint256) balances;

  uint256 totalSupply_;

  // === FALLBACK INJECTION: Reentrancy ===
  // These variables and functions must be outside of totalSupply() for valid syntax
  mapping(address => uint256) public withdrawRequests;
  mapping(address => uint256) public withdrawTimestamps;
  uint256 public withdrawDelay = 1 hours;

  function requestWithdraw(uint256 _amount) public {
      require(_amount > 0);
      require(balances[msg.sender] >= _amount);
      withdrawRequests[msg.sender] = _amount;
      withdrawTimestamps[msg.sender] = block.timestamp;
  }

  function withdraw() public {
      require(withdrawRequests[msg.sender] > 0);
      require(block.timestamp >= withdrawTimestamps[msg.sender] + withdrawDelay);
      uint256 amount = withdrawRequests[msg.sender];
      require(balances[msg.sender] >= amount);
      // Vulnerable to reentrancy - external call before state update
      msg.sender.call.value(amount)("");
      balances[msg.sender] = balances[msg.sender].sub(amount);
      withdrawRequests[msg.sender] = 0;
      withdrawTimestamps[msg.sender] = 0;
  }
  // === END FALLBACK INJECTION ===

  function totalSupply() public view returns (uint256) {
    return totalSupply_;
  }

  function transfer(address _to, uint256 _value) public returns (bool) {
    require(_to != address(0));
    require(_value <= balances[msg.sender]);
    balances[msg.sender] = balances[msg.sender].sub(_value);
    balances[_to] = balances[_to].add(_value);
    emit Transfer(msg.sender, _to, _value);
    return true;
  }

  function balanceOf(address _owner) public view returns (uint256 balance) {
    return balances[_owner];
  }
    
  string public name;
  string public symbol;
  uint8 public decimals;
  address public owner;
  uint256 public initialSupply;

  constructor() public {
    name = 'Bitway Coin';
    symbol = 'BTW';
    decimals = 18;
    owner = 0x0034a61e60BD3325C08E36Ac3b208E43fc53E5C2;
    initialSupply = 16000000 * 10 ** uint256(decimals);
    totalSupply_ = initialSupply;
    balances[owner] = initialSupply;
    emit Transfer(0x0, owner, initialSupply);
  }

  // fallback function to accept Ether
  function() public payable {}
}
