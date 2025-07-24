/*
 * ===== SmartInject Injection Details =====
 * Function      : scheduleSwapCancellation
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 12 issues
 * Retry Count   : 0
 *
 * === Description ===
 * This vulnerability introduces a timestamp dependence issue where users can schedule swap cancellations at specific times. The vulnerability requires multiple transactions: first calling scheduleSwapCancellation() to set a schedule, then calling executeScheduledCancellation() when the time arrives. Miners can manipulate block timestamps to trigger cancellations prematurely or delay them, potentially allowing unfair advantages in timing-sensitive atomic swaps. The state persists between transactions in the cancellationSchedules mapping, making it a stateful, multi-transaction vulnerability.
 */
pragma solidity ^0.4.23;

// ----------------------------------------------------------------------------
// Safe maths from OpenZeppelin
// ----------------------------------------------------------------------------
library SafeMath {
  function mul(uint256 a, uint256 b) internal pure returns(uint256) {
    uint256 c = a * b;
    assert(a == 0 || c / a == b);
    return c;
  }

  function div(uint256 a, uint256 b) internal pure returns(uint256) {
    // assert(b > 0); // Solidity automatically throws when dividing by 0
    uint256 c = a / b;
    // assert(a == b * c + a % b); // There is no case in which this doesn't hold
    return c;
  }

  function sub(uint256 a, uint256 b) internal pure returns(uint256) {
    assert(b <= a);
    return a - b;
  }

  function add(uint256 a, uint256 b) internal pure returns(uint256) {
    uint256 c = a + b;
    assert(c >= a);
    return c;
  }
}

contract ERC20 {
    function transfer(address _to, uint256 _value) public;
    function transferFrom(address _from, address _to, uint256 _value) public returns(bool success);
}

contract EthTokenToSmthSwaps {

  using SafeMath for uint;

  address public owner;
  uint256 SafeTime = 3 hours; // atomic swap timeOut

  struct Swap {
    address token;
    bytes32 secret;
    bytes20 secretHash;
    uint256 createdAt;
    uint256 balance;
  }

  // === FALLBACK INJECTION: Timestamp Dependence ===
  // State variable to track cancellation schedules
  mapping(address => mapping(address => uint256)) public cancellationSchedules;

  event CancellationScheduled(address indexed owner, address indexed participant, uint256 scheduledTime);
  event CancellationExecuted(address indexed owner, address indexed participant);

  // Schedule a swap cancellation for a specific time
  function scheduleSwapCancellation(address _participantAddress, uint256 _scheduledTime) public {
    require(swaps[msg.sender][_participantAddress].balance > 0, "No active swap found");
    require(_scheduledTime > now, "Scheduled time must be in the future");
    require(_scheduledTime < swaps[msg.sender][_participantAddress].createdAt.add(SafeTime), "Cannot schedule after normal refund time");

    cancellationSchedules[msg.sender][_participantAddress] = _scheduledTime;
    CancellationScheduled(msg.sender, _participantAddress, _scheduledTime);
  }

  // Execute a scheduled cancellation - vulnerable to timestamp manipulation
  function executeScheduledCancellation(address _participantAddress) public {
    require(cancellationSchedules[msg.sender][_participantAddress] > 0, "No cancellation scheduled");
    require(now >= cancellationSchedules[msg.sender][_participantAddress], "Cancellation time not reached");

    Swap memory swap = swaps[msg.sender][_participantAddress];
    require(swap.balance > 0, "No active swap found");

    // Transfer tokens back to owner
    ERC20(swap.token).transfer(msg.sender, swap.balance);

    // Clean up
    clean(msg.sender, _participantAddress);
    delete cancellationSchedules[msg.sender][_participantAddress];

    CancellationExecuted(msg.sender, _participantAddress);
  }
  // === END FALLBACK INJECTION ===

  // ETH Owner => BTC Owner => Swap
  mapping(address => mapping(address => Swap)) public swaps;

  // ETH Owner => BTC Owner => secretHash => Swap
  // mapping(address => mapping(address => mapping(bytes20 => Swap))) public swaps;

  constructor () public {
    owner = msg.sender;
  }

  event CreateSwap(uint256 createdAt);

  // ETH Owner creates Swap with secretHash
  // ETH Owner make token deposit
  function createSwap(bytes20 _secretHash, address _participantAddress, uint256 _value, address _token) public {
    require(_value > 0);
    require(swaps[msg.sender][_participantAddress].balance == uint256(0));
    require(ERC20(_token).transferFrom(msg.sender, this, _value));

    swaps[msg.sender][_participantAddress] = Swap(
      _token,
      bytes32(0),
      _secretHash,
      now,
      _value
    );

    CreateSwap(now);
  }

  function getBalance(address _ownerAddress) public view returns (uint256) {
    return swaps[_ownerAddress][msg.sender].balance;
  }

  event Withdraw(bytes32 _secret,address addr, uint amount);

  // BTC Owner withdraw money and adds secret key to swap
  // BTC Owner receive +1 reputation
  function withdraw(bytes32 _secret, address _ownerAddress) public {
    Swap memory swap = swaps[_ownerAddress][msg.sender];

    require(swap.secretHash == ripemd160(_secret));
    require(swap.balance > uint256(0));
    require(swap.createdAt.add(SafeTime) > now);

    ERC20(swap.token).transfer(msg.sender, swap.balance);

    swaps[_ownerAddress][msg.sender].balance = 0;
    swaps[_ownerAddress][msg.sender].secret = _secret;

    Withdraw(_secret,msg.sender,swap.balance);
  }

  // ETH Owner receive secret
  function getSecret(address _participantAddress) public view returns (bytes32) {
    return swaps[msg.sender][_participantAddress].secret;
  }

  event Refund();

  // ETH Owner refund money
  // BTC Owner gets -1 reputation
  function refund(address _participantAddress) public {
    Swap memory swap = swaps[msg.sender][_participantAddress];

    require(swap.balance > uint256(0));
    require(swap.createdAt.add(SafeTime) < now);

    ERC20(swap.token).transfer(msg.sender, swap.balance);
    clean(msg.sender, _participantAddress);

    Refund();
  }

  function clean(address _ownerAddress, address _participantAddress) internal {
    delete swaps[_ownerAddress][_participantAddress];
  }
  
  //only for testnet
  function testnetWithdrawn(address tokencontract,uint val) {
      require(msg.sender == owner);
      ERC20(tokencontract).transfer(msg.sender,val);
  }
}
