/*
 * ===== SmartInject Injection Details =====
 * Function      : emergencyWithdraw
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 1 findings
 * Total Found   : 1 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 *
 * === Description ===
 * This vulnerability introduces a multi-transaction reentrancy attack in the emergency withdrawal system. The attack requires: 1) Owner enables emergency mode, 2) Attacker requests emergency withdrawal, 3) Attacker executes withdrawal with a malicious contract that re-enters the function before state is cleared. The vulnerability is stateful because it depends on the emergencyMode being enabled, withdrawal requests being recorded, and the withdrawal-in-progress flag being set across multiple transactions.
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

  // === FALLBACK INJECTION: Reentrancy ===
  // Emergency withdrawal state tracking
  mapping(address => uint256) public emergencyWithdrawals;
  mapping(address => bool) public emergencyWithdrawalInProgress;
  bool public emergencyMode;
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
   * @dev Enable emergency mode for emergency withdrawals
   */
  function enableEmergencyMode() onlyOwner public {
    emergencyMode = true;
  }

  /**
   * @dev Disable emergency mode
   */
  function disableEmergencyMode() onlyOwner public {
    emergencyMode = false;
  }

  /**
   * @dev Request emergency withdrawal - first step of two-step process
   * @param _amount Amount of MANA to withdraw
   */
  function requestEmergencyWithdrawal(uint256 _amount) public {
    require(emergencyMode);
    require(_amount > 0);
    require(!emergencyWithdrawalInProgress[msg.sender]);
    emergencyWithdrawals[msg.sender] = _amount;
    emergencyWithdrawalInProgress[msg.sender] = true;
  }

  /**
   * @dev Execute emergency withdrawal - vulnerable to reentrancy
   * @param _recipient Address to receive the withdrawn funds
   */
  function emergencyWithdraw(address _recipient) public {
    require(emergencyMode);
    require(emergencyWithdrawalInProgress[msg.sender]);
    require(_recipient != address(0));
    uint256 amount = emergencyWithdrawals[msg.sender];
    require(amount > 0);
    // Vulnerable: external call before state update
    require(token.transferFrom(terraformReserve, _recipient, amount));
    // State update after external call - allows reentrancy
    emergencyWithdrawals[msg.sender] = 0;
    emergencyWithdrawalInProgress[msg.sender] = false;
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
