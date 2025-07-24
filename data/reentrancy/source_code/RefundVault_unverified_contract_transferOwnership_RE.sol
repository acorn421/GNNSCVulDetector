/*
 * ===== SmartInject Injection Details =====
 * Function      : transferOwnership
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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the previous owner before updating the owner state. This creates a window where the contract state is inconsistent - the external call is made while the old owner is still recorded, allowing reentrancy attacks that exploit the temporary state inconsistency across multiple transactions.
 * 
 * **Specific Changes Made:**
 * 1. Added an external call to `owner.call()` with `onOwnershipTransferred` callback before state update
 * 2. The call is made to the current owner (before the state change) notifying them of the transfer
 * 3. The owner state is updated AFTER the external call, creating a reentrancy window
 * 4. Added a condition to avoid self-notification when owner transfers to themselves
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 1. **Transaction 1**: Current owner is a malicious contract. Someone calls `transferOwnership(newOwner)`
 * 2. **During callback**: The malicious owner contract receives `onOwnershipTransferred` callback while still being the recorded owner
 * 3. **Reentrancy Attack**: In the callback, the malicious contract calls other contract functions that depend on `onlyOwner` modifier (like `enableRefunds`, `close`, `deposit`, etc.)
 * 4. **Transaction 2**: The malicious contract can manipulate contract state (change vault state, withdraw funds, etc.) before the ownership transfer completes
 * 5. **State Persistence**: The effects of the malicious actions persist even after ownership transfer completes
 * 
 * **Why Multi-Transaction is Required:**
 * - The vulnerability requires the attacker to first become the owner in a previous transaction
 * - The actual exploitation happens during the ownership transfer callback window
 * - The attacker needs to call other contract functions during reentrancy, which may require additional state setup
 * - The persistent state changes from the attack remain even after the ownership transfer completes, requiring multiple transactions to fully exploit the accumulated state inconsistency
 * 
 * This creates a realistic scenario where an attacker could manipulate the RefundVault state (enable refunds, close vault, withdraw funds) during the brief window when they are still the owner but a transfer is in progress.
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
    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
    
    // Notify previous owner about ownership transfer
    if (owner != address(0) && owner != msg.sender) {
        // External call before state update - vulnerable to reentrancy
        (bool success, ) = owner.call(
            abi.encodeWithSignature("onOwnershipTransferred(address,address)", owner, newOwner)
        );
        // Continue execution regardless of callback success
    }
    
    // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
    OwnershipTransferred(owner, newOwner);
    owner = newOwner;
// ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
}
// ===== SMARTINJECT: Reentrancy VULNERABILITY END =====

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