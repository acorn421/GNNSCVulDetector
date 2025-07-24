/*
 * ===== SmartInject Injection Details =====
 * Function      : transferOwnership
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 2 findings
 * Total Found   : 2 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a multi-transaction reentrancy vulnerability by adding an external call to notify the new owner before updating the owner state. This creates a classic reentrancy pattern where:
 * 
 * **Specific Changes Made:**
 * 1. Added an external call to `newOwner.call()` before the state update (`owner = newOwner`)
 * 2. The call attempts to notify the new owner via `onOwnershipTransfer(address)` callback
 * 3. Added a check for contract code existence to make the call realistic
 * 4. The external call happens BEFORE the critical state change
 * 
 * **Multi-Transaction Exploitation Pattern:**
 * 1. **Transaction 1**: Attacker deploys a malicious contract with `onOwnershipTransfer()` function
 * 2. **Transaction 2**: Current owner calls `transferOwnership()` with malicious contract address
 * 3. **During Transaction 2**: The malicious contract's `onOwnershipTransfer()` is called while `owner` is still the old owner
 * 4. **Reentrancy Attack**: The malicious contract can call back into `transferOwnership()` or other `onlyOwner` functions, potentially:
 *    - Calling `transferOwnership()` again to redirect ownership to a different address
 *    - Calling other `onlyOwner` functions like `burnMana()` or `transferBackMANA()` with the old owner's privileges
 *    - Setting up complex multi-step attacks that require the intermediate state
 * 
 * **Why Multi-Transaction is Required:**
 * - The attacker must first deploy the malicious contract (Transaction 1)
 * - The vulnerability is only triggered when the legitimate owner calls `transferOwnership()` (Transaction 2)
 * - The exploit depends on the persistent state of the deployed malicious contract
 * - The attack leverages the fact that `owner` hasn't been updated yet during the callback, allowing abuse of the old owner's privileges
 * - Full exploitation may require additional transactions to complete the attack chain (e.g., draining funds, setting up backdoors)
 * 
 * This vulnerability is realistic because owner notification is a common pattern in production contracts, and the placement of the external call before state updates is a subtle but critical flaw that creates the reentrancy window.
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
    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
    
    // Notify new owner before state change - creates reentrancy vulnerability
    if (newOwner != address(0)) { // Dummy check to replicate intended logic in legacy Solidity
        // low-level call, manually coding vulnerable pattern
        // Passing ABI-encoded call data as in the original
        bool success = newOwner.call(bytes4(keccak256("onOwnershipTransfer(address)")), owner);
        require(success);
    }
    
    // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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
