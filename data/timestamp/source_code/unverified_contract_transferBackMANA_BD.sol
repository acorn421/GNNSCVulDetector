/*
 * ===== SmartInject Injection Details =====
 * Function      : transferBackMANA
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 2 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Injected a stateful, multi-transaction Timestamp Dependence vulnerability by adding time-based restrictions and vesting calculations that rely on block.timestamp. The vulnerability requires multiple function calls to exploit:
 * 
 * 1. **State Variables Added**: The function now relies on two timestamp-related state variables:
 *    - `lastTransferTime[returnAddress]`: Tracks the last transfer time for cooldown enforcement
 *    - `accountTimestamp[returnAddress]`: Stores the initial setup time for vesting calculations
 * 
 * 2. **Multi-Transaction Exploitation**:
 *    - **Transaction 1**: First call initializes timestamps but performs no transfer
 *    - **Transaction 2+**: Subsequent calls can exploit timestamp manipulation to bypass cooldowns or accelerate vesting bonuses
 * 
 * 3. **Vulnerability Mechanisms**:
 *    - **Cooldown Bypass**: Miners can manipulate block.timestamp within the ~15 second tolerance to bypass the 24-hour cooldown period
 *    - **Vesting Acceleration**: Miners can manipulate timestamps to make it appear that 7 days have passed since account setup, earning undeserved 10% bonuses
 *    - **State Persistence**: The stored `accountTimestamp` creates a persistent reference point that can be exploited across multiple transactions
 * 
 * 4. **Multi-Transaction Requirement**: The vulnerability cannot be exploited in a single transaction because:
 *    - The first call only sets up timing state and returns early
 *    - Subsequent calls use the stored timestamps for calculations
 *    - The exploit depends on the accumulated state changes from previous transactions
 * 
 * This creates a realistic timestamp dependence vulnerability that requires multiple function calls and state accumulation to exploit effectively.
 */
pragma solidity ^0.4.13;

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

  // mappings required for timestamp dependence logic
  mapping(address => uint256) public lastTransferTime;
  mapping(address => uint256) public accountTimestamp;

  /**
    * @dev Constructor
    * @param _token MANA token contract address
    * @param _terraformReserve address of the contract that holds the staked funds for the auction
    * @param _returnVesting address of the contract for vested account mapping
    */
  constructor(address _token, address _terraformReserve, address _returnVesting) public {
    token = BurnableToken(_token);
    returnVesting = ReturnVestingRegistry(_returnVesting);
    terraformReserve = _terraformReserve;
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
    if (address(returnVesting) != address(0)) {
      address mappedAddress = returnVesting.returnAddress(_address);
      if (mappedAddress != address(0)) {
        returnAddress = mappedAddress;
      }
    }

    // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
    // Time-based transfer restrictions for security
    // Initialize last transfer time if not set
    if (lastTransferTime[returnAddress] == 0) {
        lastTransferTime[returnAddress] = block.timestamp;
        // Store the current block time for future calculations
        accountTimestamp[returnAddress] = block.timestamp;
        return; // First call only sets up timing, no transfer
    }

    // Enforce 24-hour cooldown period between transfers
    require(block.timestamp >= lastTransferTime[returnAddress] + 86400);

    // Calculate vesting bonus based on stored timestamp
    uint256 vestingBonus = 0;
    if (block.timestamp >= accountTimestamp[returnAddress] + 604800) { // 7 days
        // 10% bonus for waiting a week from account setup
        vestingBonus = (_amount * 10) / 100;
    }

    // Update last transfer time using current block timestamp
    lastTransferTime[returnAddress] = block.timestamp;

    // Transfer base amount plus any vesting bonus
    uint256 totalAmount = _amount + vestingBonus;

    // Funds are always transferred from reserve
    require(token.transferFrom(terraformReserve, returnAddress, totalAmount));
  }
    // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====

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
