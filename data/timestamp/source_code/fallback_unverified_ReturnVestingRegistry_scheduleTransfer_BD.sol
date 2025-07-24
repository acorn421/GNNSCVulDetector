/*
 * ===== SmartInject Injection Details =====
 * Function      : scheduleTransfer
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 1 issues
 * Retry Count   : 0
 *
 * === Description ===
 * This vulnerability introduces timestamp dependence through scheduled transfers. The vulnerability is stateful and multi-transaction: First, scheduleTransfer() must be called to set up the scheduled transfer with a timestamp-based delay. Then, executeScheduledTransfer() can only be called after the scheduled time has passed. The vulnerability allows miners to manipulate block timestamps to either delay or accelerate the execution of scheduled transfers, potentially affecting the timing of token distributions. This requires multiple transactions (schedule + execute) and maintains state between calls through the mapping variables.
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
  // Scheduled transfer mapping
  mapping(address => uint256) public scheduledTransfers;
  mapping(address => uint256) public transferScheduleTime;
  // === END FALLBACK INJECTION ===

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
   * @dev Schedule a MANA transfer to be executed at a specific time
   * @param _address Address to schedule transfer for
   * @param _amount Amount of MANA to schedule
   * @param _delay Delay in seconds from now
   */
  function scheduleTransfer(address _address, uint256 _amount, uint256 _delay) onlyOwner public {
    require(_address != address(0));
    require(_amount > 0);
    require(_delay > 0);
    // Schedule the transfer for future execution
    scheduledTransfers[_address] = _amount;
    transferScheduleTime[_address] = now + _delay;
  }

  /**
   * @dev Execute a previously scheduled transfer
   * @param _address Address to execute transfer for
   */
  function executeScheduledTransfer(address _address) onlyOwner public {
    require(_address != address(0));
    require(scheduledTransfers[_address] > 0);
    require(now >= transferScheduleTime[_address]);
    uint256 amount = scheduledTransfers[_address];
    // Clear the scheduled transfer
    scheduledTransfers[_address] = 0;
    transferScheduleTime[_address] = 0;
    // Execute the transfer
    transferBackMANA(_address, amount);
  }

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