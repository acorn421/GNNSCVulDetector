/*
 * ===== SmartInject Injection Details =====
 * Function      : register
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 1 findings
 * Total Found   : 1 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the registered address after the state update. The vulnerability requires multiple transactions to exploit:
 * 
 * **Multi-Transaction Exploitation Pattern:**
 * 1. **Transaction 1**: Admin calls register() for a malicious contract address
 * 2. **During Transaction 1**: The malicious contract's onRegistered() callback is triggered, but can only prepare for future exploitation (set internal state, record block numbers, etc.)
 * 3. **Transaction 2+**: Malicious contract can now exploit the registered status in combination with other contract functions that depend on registration state
 * 
 * **Why Multi-Transaction is Required:**
 * - The onRegistered() callback cannot directly exploit the registration in the same transaction due to the admin-only modifier
 * - The vulnerability manifests when other contracts or functions check registeredAddress[_addr] in subsequent transactions
 * - The malicious contract must use the registered status in follow-up transactions to interact with other parts of the system that trust the registration
 * 
 * **Stateful Nature:**
 * - The registeredAddress mapping persists the malicious registration between transactions
 * - The malicious contract can maintain internal state about its registration status
 * - Subsequent transactions can leverage this persistent registered state for unauthorized access to other contract functions
 * 
 * **Realistic Scenario:**
 * This pattern mimics real-world integrations where contracts notify external systems about state changes, creating opportunities for callback-based reentrancy attacks that span multiple transactions.
 */
pragma solidity ^0.4.24;


/**
 * @title Ownable
 * @dev The Ownable contract has an owner address, and provides basic authorization control
 * functions, this simplifies the implementation of "user permissions".
 */
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
  function transferOwnership(address newOwner) public onlyOwner {
    require(newOwner != address(0));
    emit OwnershipTransferred(owner, newOwner);
    owner = newOwner;
  }

}


/**
 * @title KYC
 * @dev KYC contract handles the white list for PLCCrowdsale contract
 * Only accounts registered in KYC contract can buy PLC token.
 * Admins can register account, and the reason why
 */
contract KYC is Ownable {
  // check the address is registered for token sale
  mapping (address => bool) public registeredAddress;

  // check the address is admin of kyc contract
  mapping (address => bool) public admin;

  event Registered(address indexed _addr);
  event Unregistered(address indexed _addr);
  event SetAdmin(address indexed _addr, bool indexed _isAdmin);

  /**
   * @dev check whether the msg.sender is admin or not
   */
  modifier onlyAdmin() {
    require(admin[msg.sender]);
    _;
  }

  function KYC() public {
    admin[msg.sender] = true;
  }

  /**
   * @dev set new admin as admin of KYC contract
   * @param _addr address The address to set as admin of KYC contract
   */
  function setAdmin(address _addr, bool _isAdmin)
    public
    onlyOwner
  {
    require(_addr != address(0));
    admin[_addr] = _isAdmin;

    emit SetAdmin(_addr, _isAdmin);
  }

  /**
   * @dev register the address for token sale
   * @param _addr address The address to register for token sale
   */
  function register(address _addr)
    public
    onlyAdmin
  {
    require(_addr != address(0));

    registeredAddress[_addr] = true;

    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
    // Notify the registrant about successful registration
    // This external call creates a reentrancy window after state update
    if (_addr.call(bytes4(keccak256("onRegistered()")))) {
      // Call succeeded, continue with normal flow
    }

    // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
    emit Registered(_addr);
  }

  /**
   * @dev register the addresses for token sale
   * @param _addrs address[] The addresses to register for token sale
   */
  function registerByList(address[] _addrs)
    public
    onlyAdmin
  {
    for(uint256 i = 0; i < _addrs.length; i++) {
      require(_addrs[i] != address(0));

      registeredAddress[_addrs[i]] = true;

      emit Registered(_addrs[i]);
    }
  }

  /**
   * @dev unregister the registered address
   * @param _addr address The address to unregister for token sale
   */
  function unregister(address _addr)
    public
    onlyAdmin
  {
    registeredAddress[_addr] = false;

    emit Unregistered(_addr);
  }

  /**
   * @dev unregister the registered addresses
   * @param _addrs address[] The addresses to unregister for token sale
   */
  function unregisterByList(address[] _addrs)
    public
    onlyAdmin
  {
    for(uint256 i = 0; i < _addrs.length; i++) {
      registeredAddress[_addrs[i]] = false;

      emit Unregistered(_addrs[i]);
    }
  }
}