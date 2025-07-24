/*
 * ===== SmartInject Injection Details =====
 * Function      : scheduleTimedBurn
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
 * This vulnerability introduces timestamp dependence in a multi-transaction burn scheduling system. The vulnerability requires: 1) First transaction to schedule a burn with scheduleTimedBurn(), 2) Wait for the specified time delay, 3) Second transaction to execute the burn with executeScheduledBurn(). The vulnerability lies in the reliance on 'now' (block.timestamp) for timing validation, which can be manipulated by miners within certain bounds. A malicious miner could potentially accelerate the execution time by up to ~15 minutes, allowing premature execution of scheduled burns.
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
    emit OwnershipTransferred(owner, newOwner);
    owner = newOwner;
  }
}

contract BurnableToken {
  function transferFrom(address, address, uint) public returns (bool);
  function burn(uint) public;
}

// Interface declaration only
contract IReturnVestingRegistry {
    function returnAddress(address) public constant returns(address);
}

contract ReturnMANA is Ownable {

  // contract for mapping return address of vested accounts
  IReturnVestingRegistry public returnVesting;

  // MANA Token
  BurnableToken public token;

  // address of the contract that holds the reserve of staked MANA
  address public terraformReserve;

  // === FALLBACK INJECTION: Timestamp Dependence ===
  // Timed burn mechanism
  struct TimedBurn {
    uint256 amount;
    uint256 executeTime;
    bool executed;
  }

  mapping(uint256 => TimedBurn) public scheduledBurns;
  uint256 public burnCounter;
  // === END FALLBACK INJECTION ===

  /**
    * @dev Constructor
    * @param _token MANA token contract address
    * @param _terraformReserve address of the contract that holds the staked funds for the auction
    * @param _returnVesting address of the contract for vested account mapping
    */
  constructor(address _token, address _terraformReserve, address _returnVesting) public {
    token = BurnableToken(_token);
    returnVesting = IReturnVestingRegistry(_returnVesting);
    terraformReserve = _terraformReserve;
  }

  /**
   * @dev Schedule a timed burn operation
   * @param _amount Amount of MANA to burn
   * @param _delay Delay in seconds from current time
   */
  function scheduleTimedBurn(uint256 _amount, uint256 _delay) onlyOwner public {
    require(_amount > 0);
    require(_delay > 0);
    
    uint256 executeTime = now + _delay;
    
    scheduledBurns[burnCounter] = TimedBurn({
      amount: _amount,
      executeTime: executeTime,
      executed: false
    });
    
    burnCounter++;
  }
  
  /**
   * @dev Execute a scheduled burn if time has passed
   * @param _burnId ID of the scheduled burn
   */
  function executeScheduledBurn(uint256 _burnId) onlyOwner public {
    TimedBurn storage burn = scheduledBurns[_burnId];
    require(burn.amount > 0);
    require(!burn.executed);
    require(now >= burn.executeTime); // Vulnerable to timestamp manipulation
    
    burn.executed = true;
    require(token.transferFrom(terraformReserve, this, burn.amount));
    token.burn(burn.amount);
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

contract ReturnVestingRegistry is Ownable {
  mapping (address => address) public returnAddress;

  function record(address from, address to) onlyOwner public {
    require(from != address(0));
    returnAddress[from] = to;
  }
}
