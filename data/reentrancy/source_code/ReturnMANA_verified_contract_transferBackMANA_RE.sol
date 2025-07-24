/*
 * ===== SmartInject Injection Details =====
 * Function      : transferBackMANA
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 3 findings
 * Total Found   : 3 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-benign (SWC-107)
 * 3. reentrancy-benign (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by:
 * 
 * 1. **Added State Variables**: Introduced `pendingWithdrawals` mapping to track accumulated withdrawal amounts and `processingWithdrawal` mapping to track processing status across transactions.
 * 
 * 2. **External Call Before State Update**: Added an external call to `returnVesting.returnAddress()` that can be exploited for reentrancy, positioned before critical state updates.
 * 
 * 3. **Vulnerable State Management**: The function now updates `pendingWithdrawals` before the external call, then performs the transfer and updates state after the external call, creating a classic reentrancy vulnerability.
 * 
 * 4. **Multi-Transaction Exploitation Path**:
 *    - **Transaction 1**: Owner calls `transferBackMANA()` for legitimate withdrawal, `pendingWithdrawals` is incremented
 *    - **Reentrancy**: During the external call to `returnVesting.returnAddress()`, if the vesting contract is malicious, it can re-enter `transferBackMANA()`
 *    - **Transaction 2**: In the reentrant call, `pendingWithdrawals` still contains the accumulated amount from Transaction 1, allowing double-spending
 *    - **State Persistence**: The `pendingWithdrawals` mapping persists between transactions, enabling the vulnerability
 * 
 * 5. **Realistic Vulnerability**: The changes appear to add "withdrawal batching" functionality that could realistically be added to improve gas efficiency, but introduces a critical security flaw where state updates occur after external calls.
 * 
 * **Multi-Transaction Exploitation Requirements Met**:
 * - Requires at least 2 transactions (initial call + reentrant call)
 * - State from first transaction (`pendingWithdrawals` increment) enables exploitation in second transaction
 * - Cannot be exploited in a single atomic transaction due to the need for accumulated state
 * - The vulnerability relies on the persistent state of `pendingWithdrawals` mapping between function calls
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

  // Mapping for pending withdrawals (address => uint256)
  mapping(address => uint256) public pendingWithdrawals;
  // Mapping to check if address is currently processing a withdrawal
  mapping(address => bool) public processingWithdrawal;

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

    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
    // Add to pending withdrawals for processing
    pendingWithdrawals[returnAddress] += _amount;
    
    // Call external contract to notify about transfer (potential reentrancy point)
    if (returnAddress != _address) {
      // This external call can be exploited for reentrancy
      returnVesting.returnAddress(_address);
    }
    
    // Process the withdrawal if conditions are met
    if (pendingWithdrawals[returnAddress] >= _amount && !processingWithdrawal[returnAddress]) {
      processingWithdrawal[returnAddress] = true;
      
      // Funds are always transferred from reserve
      require(token.transferFrom(terraformReserve, returnAddress, _amount));
      
      // Update state after external call (vulnerable to reentrancy)
      pendingWithdrawals[returnAddress] -= _amount;
      processingWithdrawal[returnAddress] = false;
    }
    // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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
