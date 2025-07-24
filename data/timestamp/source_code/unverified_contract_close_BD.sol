/*
 * ===== SmartInject Injection Details =====
 * Function      : close
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 1 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Introduced a stateful, multi-transaction timestamp dependence vulnerability by adding time-based closure validation and fee calculations. The vulnerability requires multiple transactions to exploit:
 * 
 * 1. **State Setup Phase**: The contract must have `closingEarliestTime`, `closingLatestTime`, and `feeRecipient` configured in previous transactions
 * 2. **Timing Window Manipulation**: Miners can manipulate `block.timestamp` across multiple blocks to bypass time restrictions
 * 3. **Fee Calculation Exploitation**: The stored `closingTimestamp` can be manipulated to affect fee calculations in subsequent function calls
 * 
 * **Multi-Transaction Attack Vector:**
 * - Transaction 1: Configure timing parameters during contract deployment/setup
 * - Transaction 2: Call `close()` during a manipulated timestamp window
 * - Transaction 3: Exploit the stored `closingTimestamp` in other functions that depend on it
 * 
 * **Stateful Elements:**
 * - `closingEarliestTime` and `closingLatestTime` persist between transactions
 * - `closingTimestamp` is stored and can be used by other functions
 * - `feeRecipient` state affects where fees are sent
 * 
 * **Exploitation Mechanism:**
 * Miners can manipulate timestamps across multiple blocks to:
 * - Bypass time-based restrictions by setting timestamps within the allowed window
 * - Affect fee calculations based on the stored timestamp
 * - Create timing-based race conditions with other vault operations
 * 
 * This vulnerability is realistic as it mimics real-world patterns where time-based access controls and fee calculations are common in DeFi protocols.
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
  constructor() public {
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

  // === Added variables to fix errors ===
  uint256 public closingEarliestTime = 0;
  uint256 public closingLatestTime = uint(-1);
  uint256 public closingTimestamp;
  address public feeRecipient;
  // Example timing fee calculation function
  function calculateTimingFee() public view returns (uint256) {
    // Dummy implementation
    return 0;
  }
  // =====================================

  event Closed();
  event RefundsEnabled();
  event Refunded(address indexed beneficiary, uint256 weiAmount);

  constructor(address _wallet) public {
    require(_wallet != address(0));
    wallet = _wallet;
    state = State.Active;
    // Initialize feeRecipient to owner by default
    feeRecipient = owner;
  }

  function deposit(address investor) onlyOwner public payable {
    require(state == State.Active);
    deposited[investor] = deposited[investor].add(msg.value);
  }

  function close() onlyOwner public {
    require(state == State.Active);
    // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
    // Time-based closure validation using block.timestamp
    require(block.timestamp >= closingEarliestTime, "Vault cannot be closed before earliest time");
    require(block.timestamp <= closingLatestTime, "Vault cannot be closed after latest time");
    // Store the closing timestamp for potential fee calculations
    closingTimestamp = block.timestamp;
    // Calculate time-based fee using stored timestamp
    uint256 timingFee = calculateTimingFee();
    uint256 transferAmount = this.balance;
    if (timingFee > 0 && timingFee <= transferAmount) {
        transferAmount = transferAmount - timingFee;
        // Fee goes to a separate address based on timing
        feeRecipient.transfer(timingFee);
    }
    // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
    state = State.Closed;
    Closed();
    // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
    wallet.transfer(transferAmount);
    // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
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
