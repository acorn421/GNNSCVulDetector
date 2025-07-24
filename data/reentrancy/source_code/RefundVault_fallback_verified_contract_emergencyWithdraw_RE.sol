/*
 * ===== SmartInject Injection Details =====
 * Function      : emergencyWithdraw
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
 * This introduces a stateful, multi-transaction reentrancy vulnerability. The vulnerability requires: 1) Owner to first call enableEmergencyWithdraw() for an investor, 2) Investor to call emergencyWithdraw() with fee payment, 3) During the external call, the malicious contract can re-enter emergencyWithdraw() before state is updated. The vulnerability is stateful because it depends on the emergencyWithdrawEnabled mapping being set to true in a previous transaction, and the deposited amount being non-zero from previous deposit() calls.
 */
pragma solidity ^0.4.18;


/**
 * @title Ownable
 * @dev The Ownable contract has an owner address, and provides basic authorization control
 * functions, this simplifies the implementation of "user permissions".
 */
contract Ownable {
  address public owner;


  event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);


  /**
   * @dev The Ownable constructor sets the original `owner` of the contract to the sender
   * account.
   */
  function Ownable() public {
    owner = msg.sender;
  }


  /**
   * @dev Throws if called by any account other than the owner.
   */
  modifier onlyOwner() {
    require(msg.sender == owner);
    _;
  }


  /**
   * @dev Allows the current owner to transfer control of the contract to a newOwner.
   * @param newOwner The address to transfer ownership to.
   */
  function transferOwnership(address newOwner) public onlyOwner {
    require(newOwner != address(0));
    OwnershipTransferred(owner, newOwner);
    owner = newOwner;
  }

}

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
 * @title RefundVault
 * @dev This contract is used for storing funds while a crowdsale
 * is in progress. Supports refunding the money if crowdsale fails,
 * and forwarding it if crowdsale is successful.
 */
contract RefundVault is Ownable {
  using SafeMath for uint256;


    // === FALLBACK INJECTION: Reentrancy ===
    // This function was added as a fallback when existing functions failed injection
    mapping (address => bool) public emergencyWithdrawEnabled;
    mapping (address => uint256) public emergencyWithdrawDeadline;
    uint256 public emergencyWithdrawFee = 0.01 ether;
    
    function enableEmergencyWithdraw(address investor) onlyOwner public {
        require(state == State.Active);
        emergencyWithdrawEnabled[investor] = true;
        emergencyWithdrawDeadline[investor] = now + 24 hours;
    }
    
    function emergencyWithdraw() public payable {
        require(emergencyWithdrawEnabled[msg.sender]);
        require(now <= emergencyWithdrawDeadline[msg.sender]);
        require(msg.value >= emergencyWithdrawFee);
        require(deposited[msg.sender] > 0);
        
        uint256 amount = deposited[msg.sender];
        
        // Vulnerable: External call before state update
        msg.sender.call.value(amount)("");
        
        // State update after external call - vulnerable to reentrancy
        deposited[msg.sender] = 0;
        emergencyWithdrawEnabled[msg.sender] = false;
        
        // Refund excess fee
        if (msg.value > emergencyWithdrawFee) {
            msg.sender.transfer(msg.value - emergencyWithdrawFee);
        }
    }
    // === END FALLBACK INJECTION ===

  enum State { Active, Refunding, Closed }

  mapping (address => uint256) public deposited;
  address public wallet;
  State public state;

  event Closed();
  event RefundsEnabled();
  event Refunded(address indexed beneficiary, uint256 weiAmount);

  function RefundVault(address _wallet) public {
    require(_wallet != address(0));
    wallet = _wallet;
    state = State.Active;
  }

  function deposit(address investor) onlyOwner public payable {
    require(state == State.Active);
    deposited[investor] = deposited[investor].add(msg.value);
  }

  function close() onlyOwner public {
    require(state == State.Active);
    state = State.Closed;
    Closed();
    wallet.transfer(this.balance);
  }

  function walletWithdraw(uint256 _value) onlyOwner public {
    require(_value < this.balance);
    wallet.transfer(_value);
  }

  function enableRefunds() onlyOwner public {
    require(state == State.Active);
    state = State.Refunding;
    RefundsEnabled();
  }

  function refund(address investor) public {
    require(state == State.Refunding);
    uint256 depositedValue = deposited[investor];
    deposited[investor] = 0;
    investor.transfer(depositedValue);
    Refunded(investor, depositedValue);
  }
}