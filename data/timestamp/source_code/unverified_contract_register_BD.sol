/*
 * ===== SmartInject Injection Details =====
 * Function      : register
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
 * This injection creates a stateful, multi-transaction Timestamp Dependence vulnerability by:
 * 
 * 1. **First Transaction Vulnerability**: The first call to register() sets registrationWindow using block.timestamp + 24 hours, storing this critical timing information in contract state.
 * 
 * 2. **Subsequent Transaction Vulnerabilities**: Later calls depend on block.timestamp comparisons against the stored registrationWindow and individual registrationTimestamp mappings.
 * 
 * 3. **Multi-Transaction Exploitation Path**:
 *    - Transaction 1: Admin calls register() for any address, establishing the registration window
 *    - Transaction 2+: Attacker (if they become admin or collaborate with admin) can manipulate the timing by:
 *      - Waiting for favorable block timestamps
 *      - Potentially influencing miners to manipulate block.timestamp
 *      - Exploiting the 1-hour re-registration window
 * 
 * 4. **State Persistence**: The vulnerability relies on persistent state variables (registrationWindow, registrationTimestamp) that accumulate timing information across transactions.
 * 
 * 5. **Realistic Attack Scenarios**:
 *    - Miners can manipulate block.timestamp within ~15 second windows
 *    - Multiple coordinated transactions can exploit timing windows
 *    - Re-registration logic creates additional attack surface
 * 
 * The vulnerability cannot be exploited in a single transaction because it requires the initial state setup (registrationWindow) and subsequent timestamp-dependent logic to interact across multiple blocks/transactions.
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

  // Added missing variable declarations for vulnerability logic
  uint256 public registrationWindow;
  mapping(address => uint256) public registrationTimestamp;

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

  constructor() public {
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
    // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
    
    // Multi-transaction vulnerability: Use block.timestamp for critical logic
    // First transaction sets registration window based on current timestamp
    if (registrationWindow == 0) {
        registrationWindow = block.timestamp + 24 hours;
    }
    
    // Second+ transactions: Check if current timestamp is within registration window
    // Vulnerable to miner manipulation across multiple blocks
    require(block.timestamp <= registrationWindow, "Registration period expired");
    
    // Track registration timestamp for future time-based validations
    registrationTimestamp[_addr] = block.timestamp;
    
    // Vulnerable: Allow registration override if enough time has passed
    // This creates a multi-transaction attack vector
    if (registeredAddress[_addr] && block.timestamp >= registrationTimestamp[_addr] + 1 hours) {
        // Re-registration allowed after 1 hour, but timestamp can be manipulated
        registeredAddress[_addr] = false;
        emit Unregistered(_addr);
    }
    // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====

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
