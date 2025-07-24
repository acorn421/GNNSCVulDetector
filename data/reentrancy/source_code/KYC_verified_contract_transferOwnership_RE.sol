/*
 * ===== SmartInject Injection Details =====
 * Function      : transferOwnership
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 3 findings
 * Total Found   : 4 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-benign (SWC-107)
 * 3. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by:
 * 
 * 1. **Added Persistent State Variables**: 
 *    - `pendingOwner`: Tracks the proposed new owner across transactions
 *    - `pendingOwnershipTimestamp`: Creates a timing window for exploitation
 * 
 * 2. **External Call Before State Finalization**: 
 *    - Added `IOwnershipNotifier(newOwner).notifyOwnershipTransfer()` call
 *    - This creates a reentrancy opportunity where the new owner can call back into the contract
 * 
 * 3. **Multi-Transaction Exploitation Pattern**:
 *    - **Transaction 1**: Attacker calls `transferOwnership(maliciousContract)` 
 *      - `pendingOwner` is set to malicious contract
 *      - External call to malicious contract occurs
 *      - Malicious contract can reenter and see both old owner still active AND pending ownership set
 *    
 *    - **Transaction 2**: Attacker exploits the inconsistent state
 *      - Can call other functions that check `pendingOwner` vs `owner`
 *      - Can manipulate admin privileges during the ownership transition
 *      - Can frontrun or exploit the timing window
 * 
 * 4. **State Persistence Vulnerability**:
 *    - The vulnerability requires the `pendingOwner` state to persist between transactions
 *    - Multiple calls are needed to fully exploit the inconsistent state between `owner` and `pendingOwner`
 *    - The timing window created by `pendingOwnershipTimestamp` enables complex multi-transaction attacks
 * 
 * 5. **Realistic Attack Vector**:
 *    - Attacker can deploy a malicious contract as the new owner
 *    - During the ownership transfer, the malicious contract can reenter and call other KYC functions
 *    - Can potentially grant admin privileges to themselves before ownership is fully transferred
 *    - Requires coordination across multiple transactions to fully exploit the state inconsistency
 * 
 * This vulnerability is stateful because it depends on the persistent state changes (`pendingOwner`, `pendingOwnershipTimestamp`) and multi-transaction because the full exploit requires multiple function calls to leverage the inconsistent state during the ownership transition period.
 */
pragma solidity ^0.4.24;

/**
 * @title IOwnershipNotifier
 * @dev Interface for external ownership notification
 */
interface IOwnershipNotifier {
    function notifyOwnershipTransfer(address previousOwner) external;
}

/**
 * @title Ownable
 * @dev The Ownable contract has an owner address, and provides basic authorization control
 * functions, this simplifies the implementation of "user permissions".
 */
contract Ownable {
  address public owner;
  address public pendingOwner;
  uint256 public pendingOwnershipTimestamp;

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
    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
    
    // Phase 1: Set pending ownership (state persists across transactions)
    pendingOwner = newOwner;
    pendingOwnershipTimestamp = block.timestamp;
    
    // External call to notify new owner - creates reentrancy opportunity
    if (isContract(newOwner)) {
        // external call without Solidity's try-catch (not available in 0.4.24)
        // but still allowing reentrancy
        IOwnershipNotifier(newOwner).notifyOwnershipTransfer(owner);
    }
    
    emit OwnershipTransferred(owner, newOwner);
    
    // Phase 2: Complete ownership transfer after external call
    // This violates Checks-Effects-Interactions pattern
    owner = newOwner;
    
    // Additional state cleanup that can be exploited
    if (pendingOwnershipTimestamp != 0) {
        pendingOwnershipTimestamp = 0;
    }
  }
    // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====

  function isContract(address _addr) internal view returns (bool) {
      uint256 size;
      assembly { size := extcodesize(_addr) }
      return size > 0;
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
