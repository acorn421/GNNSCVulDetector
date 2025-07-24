/*
 * ===== SmartInject Injection Details =====
 * Function      : scheduleRegistrationWindow
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 3 issues
 * Retry Count   : 0
 *
 * === Description ===
 * This vulnerability involves timestamp dependence across multiple transactions. The vulnerability requires: 1) Owner schedules a registration window with specific start/end times, 2) Admin activates the window when they believe it's the right time, 3) Registration occurs during the "active" window. The vulnerability lies in the reliance on 'now' (block.timestamp) which can be manipulated by miners within a ~15 second window. A malicious miner could manipulate timestamps to either prevent legitimate registrations or allow registrations outside the intended window. This is a stateful vulnerability because it requires the contract state to progress through multiple phases (scheduled -> activated -> used for registration) across different transactions.
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

  // === FALLBACK INJECTION: Timestamp Dependence ===
  // Registration window state variables
  uint256 public registrationWindowStart;
  uint256 public registrationWindowEnd;
  bool public registrationWindowActive;

  event RegistrationWindowScheduled(uint256 startTime, uint256 endTime);
  event RegistrationWindowActivated();

  /**
   * @dev Schedule a registration window for KYC registrations
   * @param _startTime Unix timestamp when registration window opens
   * @param _endTime Unix timestamp when registration window closes
   */
  function scheduleRegistrationWindow(uint256 _startTime, uint256 _endTime)
    public
    onlyOwner
  {
    require(_startTime > now);
    require(_endTime > _startTime);

    registrationWindowStart = _startTime;
    registrationWindowEnd = _endTime;
    registrationWindowActive = false;

    emit RegistrationWindowScheduled(_startTime, _endTime);
  }

  /**
   * @dev Activate the registration window if current time is within scheduled window
   */
  function activateRegistrationWindow()
    public
    onlyAdmin
  {
    require(registrationWindowStart > 0);
    require(now >= registrationWindowStart);
    require(now <= registrationWindowEnd);
    require(!registrationWindowActive);

    registrationWindowActive = true;

    emit RegistrationWindowActivated();
  }

  /**
   * @dev Register address only during active registration window
   * @param _addr address The address to register for token sale
   */
  function registerDuringWindow(address _addr)
    public
    onlyAdmin
  {
    require(_addr != address(0));
    require(registrationWindowActive);
    require(now >= registrationWindowStart);
    require(now <= registrationWindowEnd);

    registeredAddress[_addr] = true;

    emit Registered(_addr);
  }
  // === END FALLBACK INJECTION ===

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
