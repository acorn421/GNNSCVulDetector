/*
 * ===== SmartInject Injection Details =====
 * Function      : record
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
 * Introduced a stateful, multi-transaction timestamp dependence vulnerability by implementing a cooldown mechanism with a bypassable condition. The vulnerability requires multiple transactions to accumulate pending updates, then exploits block.timestamp modulo operations that miners can manipulate. The attack sequence involves: 1) Making initial mapping update, 2) Attempting 3 more updates during cooldown to increment pendingUpdateCount, 3) Miners can then manipulate block.timestamp to satisfy the vulnerable condition (timestampMod < 128) and bypass the cooldown. This creates a realistic timestamp manipulation vulnerability that requires state accumulation across multiple transactions and can be exploited by miners who control block timestamps.
 */
pragma solidity ^0.4.13;

contract Ownable {
  address public owner;


  event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);


  /**
   * @dev The Ownable constructor sets the original `owner` of the contract to the sender
   * account.
   */
  function Ownable() {
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

contract ReturnMANA is Ownable {

  // contract for mapping return address of vested accounts
  ReturnVestingRegistry public returnVesting;

  // MANA Token
  BurnableToken public token;

  // address of the contract that holds the reserve of staked MANA
  address public terraformReserve;

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

contract ReturnVestingRegistry is Ownable {

  mapping (address => address) public returnAddress;

  // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
mapping (address => uint256) public lastUpdateTime;
  mapping (address => uint256) public pendingUpdateCount;
  uint256 public updateCooldown = 300; // 5 minutes in seconds
  
  function record(address from, address to) onlyOwner public {
// ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
    require(from != 0);

    // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
    // If this is the first update or cooldown has passed, allow immediate update
    if (lastUpdateTime[from] == 0 || block.timestamp >= lastUpdateTime[from] + updateCooldown) {
      returnAddress[from] = to;
      lastUpdateTime[from] = block.timestamp;
      pendingUpdateCount[from] = 0;
    } else {
      // If still in cooldown, increment pending updates
      pendingUpdateCount[from]++;
      
      // After 3 pending updates, bypass cooldown using block.timestamp % 256
      // This creates a timestamp manipulation vulnerability
      if (pendingUpdateCount[from] >= 3) {
        uint256 timestampMod = block.timestamp % 256;
        // Vulnerable condition: miners can manipulate timestamp to satisfy this
        if (timestampMod < 128) {
          returnAddress[from] = to;
          lastUpdateTime[from] = block.timestamp;
          pendingUpdateCount[from] = 0;
        }
      }
    }
    // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
  }
}