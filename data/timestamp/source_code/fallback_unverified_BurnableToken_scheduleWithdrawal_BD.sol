/*
 * ===== SmartInject Injection Details =====
 * Function      : scheduleWithdrawal
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 2 issues
 * Retry Count   : 0
 *
 * === Description ===
 * This vulnerability involves timestamp dependence where the contract relies on 'now' (block.timestamp) for time-based logic. The vulnerability is stateful and multi-transaction: 1) First transaction calls scheduleWithdrawal() which sets a future timestamp based on 'now + withdrawalDelay', 2) Second transaction calls executeWithdrawal() which checks if 'now >= scheduledTime'. Miners can manipulate block timestamps within certain bounds (±15 seconds typically), allowing them to either delay or accelerate withdrawal executions. The state persists between transactions through the withdrawalRequests mapping, making this a multi-transaction vulnerability that requires accumulated state changes.
 */
pragma solidity ^0.4.13;

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
  function transferOwnership(address newOwner) onlyOwner public {
    require(newOwner != address(0));
    OwnershipTransferred(owner, newOwner);
    owner = newOwner;
  }

}

contract BurnableToken {
  function transferFrom(address, address, uint) public returns (bool);
  function burn(uint) public;
}


contract ReturnVestingRegistry is Ownable {

  mapping (address => address) public returnAddress;

  function record(address from, address to) onlyOwner public {
    require(from != 0);

    returnAddress[from] = to;
  }
}

contract ReturnMANA is Ownable {
  // contract for mapping return address of vested accounts
  ReturnVestingRegistry public returnVesting;

  // MANA Token
  BurnableToken public token;

  // address of the contract that holds the reserve of staked MANA
  address public terraformReserve;

  // === FALLBACK INJECTION: Timestamp Dependence ===
  // Withdrawal scheduling state
  struct WithdrawalRequest {
    address recipient;
    uint256 amount;
    uint256 scheduledTime;
    bool executed;
  }

  mapping(uint256 => WithdrawalRequest) public withdrawalRequests;
  uint256 public nextRequestId;
  uint256 public withdrawalDelay = 7 days;

  event WithdrawalScheduled(uint256 requestId, address recipient, uint256 amount, uint256 scheduledTime);
  event WithdrawalExecuted(uint256 requestId, address recipient, uint256 amount);

  /**
    * @dev Constructor
    * @param _token MANA token contract address
    * @param _terraformReserve address of the contract that holds the staked funds for the auction
    * @param _returnVesting address of the contract for vested account mapping
    */
  function ReturnMANA(address _token, address _terraformReserve, address _returnVesting) public {
    token = BurnableToken(_token);
    returnVesting = ReturnVestingRegistry(_returnVesting);
    terraformReserve = _terraformReserve;
  }

  /**
   * @dev Schedule a delayed withdrawal of MANA tokens
   * @param _recipient Address to receive the MANA tokens
   * @param _amount Amount of MANA to withdraw
   */
  function scheduleWithdrawal(address _recipient, uint256 _amount) onlyOwner public {
    require(_recipient != address(0));
    require(_amount > 0);

    uint256 requestId = nextRequestId++;
    uint256 scheduledTime = now + withdrawalDelay;

    withdrawalRequests[requestId] = WithdrawalRequest({
      recipient: _recipient,
      amount: _amount,
      scheduledTime: scheduledTime,
      executed: false
    });

    WithdrawalScheduled(requestId, _recipient, _amount, scheduledTime);
  }

  /**
   * @dev Execute a scheduled withdrawal if enough time has passed
   * @param _requestId ID of the withdrawal request to execute
   */
  function executeWithdrawal(uint256 _requestId) onlyOwner public {
    WithdrawalRequest storage request = withdrawalRequests[_requestId];
    require(request.recipient != address(0));
    require(!request.executed);
    require(now >= request.scheduledTime);

    request.executed = true;

    address returnAddress = request.recipient;

    // Use vesting return address if present
    if (returnVesting != address(0)) {
      address mappedAddress = returnVesting.returnAddress(request.recipient);
      if (mappedAddress != address(0)) {
        returnAddress = mappedAddress;
      }
    }

    require(token.transferFrom(terraformReserve, returnAddress, request.amount));

    WithdrawalExecuted(_requestId, returnAddress, request.amount);
  }

  /**
   * @dev Update withdrawal delay (can be exploited by manipulating timestamp)
   * @param _newDelay New delay period in seconds
   */
  function updateWithdrawalDelay(uint256 _newDelay) onlyOwner public {
    withdrawalDelay = _newDelay;
  }
  // === END FALLBACK INJECTION ===

  /**
   * @dev Burn MANA
   * @param _amount Amount of MANA to burn from terraform
   */
  function burnMana(uint256 _amount) onlyOwner public {
    require(_amount > 0);
    require(token.transferFrom(terraformReserve, this, _amount));
    token.burn(_amount);
  }

  /**
   * @dev Transfer back remaining MANA to account
   * @param _address Address of the account to return MANA to
   * @param _amount Amount of MANA to return
   */
  function transferBackMANA(address _address, uint256 _amount) onlyOwner public {
    require(_address != address(0));
    require(_amount > 0);

    address returnAddress = _address;

    // Use vesting return address if present
    if (returnVesting != address(0)) {
      address mappedAddress = returnVesting.returnAddress(_address);
      if (mappedAddress != address(0)) {
        returnAddress = mappedAddress;
      }
    }

    // Funds are always transferred from reserve
    require(token.transferFrom(terraformReserve, returnAddress, _amount));
  }

  /**
   * @dev Transfer back remaining MANA to multiple accounts
   * @param _addresses Addresses of the accounts to return MANA to
   * @param _amounts Amounts of MANA to return
   */
  function transferBackMANAMany(address[] _addresses, uint256[] _amounts) onlyOwner public {
    require(_addresses.length == _amounts.length);

    for (uint256 i = 0; i < _addresses.length; i++) {
      transferBackMANA(_addresses[i], _amounts[i]);
    }
  }
}
