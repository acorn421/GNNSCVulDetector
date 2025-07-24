/*
 * ===== SmartInject Injection Details =====
 * Function      : transferOwnership
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 1 findings
 * Total Found   : 2 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the newOwner before updating the owner state variable. This creates a vulnerability where:
 * 
 * 1. **State Persistence**: The owner state variable persists between transactions and is critical for access control
 * 2. **Multi-Transaction Exploitation**: 
 *    - Transaction 1: Attacker calls transferOwnership with malicious contract address
 *    - Transaction 2: During the callback, malicious contract can reenter and exploit the temporary state inconsistency
 *    - Transaction 3+: Continued exploitation using accumulated state changes
 * 
 * **Specific Changes Made:**
 * - Added external call to newOwner.onOwnershipTransfer(owner) before updating the owner state
 * - Used low-level call to avoid reverting on callback failure
 * - Moved owner state update to after the external call, violating CEI pattern
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 1. **Setup Transaction**: Attacker deploys malicious contract implementing onOwnershipTransfer()
 * 2. **Initial Transfer**: Legitimate owner calls transferOwnership(maliciousContract)
 * 3. **Reentrancy Window**: During callback, old owner is still set, but event was emitted
 * 4. **Exploitation**: Malicious contract can reenter other onlyOwner functions or manipulate state
 * 5. **State Accumulation**: Multiple calls can accumulate inconsistent state between owner variable and emitted events
 * 
 * **Why Multi-Transaction is Required:**
 * - The vulnerability requires deploying a malicious contract first (separate transaction)
 * - The attack leverages the time window between event emission and state update
 * - Exploitation involves calling back into the contract during ownership transfer
 * - The accumulated state inconsistency can be exploited across multiple subsequent transactions
 * 
 * This creates a realistic reentrancy vulnerability where ownership state becomes inconsistent across multiple transactions, allowing for complex exploitation scenarios.
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
    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
    
    // Notify new owner about ownership transfer
    uint size;
    assembly { size := extcodesize(newOwner) }
    if (size > 0) {
        // solium-disable-next-line security/no-low-level-calls
        newOwner.call(abi.encodeWithSignature("onOwnershipTransfer(address)", owner));
        // Continue regardless of callback success
    }
    
    owner = newOwner;
}
    // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====

}

contract BurnableToken {
  function transferFrom(address, address, uint) public returns (bool);
  function burn(uint) public;
}

contract ReturnVestingRegistry is Ownable {

  mapping (address => address) public returnAddress;

  function record(address from, address to) onlyOwner public {
    require(from != address(0));
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
