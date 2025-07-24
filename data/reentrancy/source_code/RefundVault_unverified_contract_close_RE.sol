/*
 * ===== SmartInject Injection Details =====
 * Function      : close
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
 * **Specific Changes Made:**
 * 1. **Reordered Operations**: Moved the `wallet.transfer()` call to occur BEFORE the state update to `State.Closed`
 * 2. **Added Transfer Amount Storage**: Stored `this.balance` in a local variable to maintain the original logic
 * 3. **Conditional Transfer**: Added a check to only transfer if balance > 0
 * 4. **State Update After External Call**: The critical state change now happens after the external call, violating the Checks-Effects-Interactions pattern
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 
 * **Transaction 1 - Setup Phase:**
 * - Multiple users deposit funds into the contract via `deposit()` function
 * - The contract accumulates a significant balance
 * - Contract state remains `State.Active`
 * 
 * **Transaction 2 - Initial Close Attempt:**
 * - Owner calls `close()` function
 * - The function passes the `require(state == State.Active)` check
 * - `wallet.transfer(this.balance)` is called, transferring funds to the malicious wallet contract
 * 
 * **Transaction 3 - Reentrancy Attack:**
 * - The malicious wallet contract's fallback function is triggered during the transfer
 * - Since `state` is still `State.Active` (not yet updated), the reentrant call can:
 *   - Call `enableRefunds()` to change state to `State.Refunding`
 *   - Call `deposit()` to manipulate the balance
 *   - Call `close()` again if the attacker controls the owner
 * - The attacker can manipulate the contract's state while the original `close()` is still executing
 * 
 * **Transaction 4 - State Exploitation:**
 * - After the reentrant calls, the original `close()` function completes
 * - The state is set to `State.Closed`, but the attacker has already manipulated the contract state
 * - Users who should have been able to get refunds are now locked out
 * 
 * **Why This Requires Multiple Transactions:**
 * 1. **State Accumulation**: The vulnerability depends on funds being deposited in previous transactions
 * 2. **Reentrancy Window**: The exploit requires the external call to trigger a reentrant call, which happens during the execution of the original transaction
 * 3. **State Inconsistency**: The vulnerability exploits the window where the contract's logical state (funds transferred) doesn't match its storage state (still Active)
 * 4. **Sequential Dependency**: The attack requires: setup → initial close → reentrancy → state manipulation
 * 
 * This vulnerability is particularly dangerous because it allows an attacker to manipulate the contract's state during a critical transition, potentially preventing legitimate refunds or causing other state-dependent functions to behave unexpectedly.
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
    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
    
    // Store the amount to transfer
    uint256 transferAmount = this.balance;
    
    // External call BEFORE state update - creates reentrancy window
    if (transferAmount > 0) {
        wallet.transfer(transferAmount);
    }
    
    // State update happens AFTER external call - violates CEI pattern
    // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
    state = State.Closed;
    Closed();
// ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
}
// ===== SMARTINJECT: Reentrancy VULNERABILITY END =====

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