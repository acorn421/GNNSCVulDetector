/*
 * ===== SmartInject Injection Details =====
 * Function      : initialize
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
 * Introduced a stateful, multi-transaction timestamp dependence vulnerability where the allocated supply depends on the time gap between successive security creations. The vulnerability requires two state variables (lastCreationTime and securityCreationTime) that persist between transactions. Attackers can exploit this by:
 * 
 * 1. First transaction: Create a security to establish a baseline timestamp
 * 2. Wait for block.timestamp manipulation or natural time progression  
 * 3. Second transaction: Create another security with timing manipulation to get increased supply allocation
 * 
 * The vulnerability is multi-transaction because:
 * - It requires at least two separate initialize() calls to exploit
 * - The first call sets up the timing state (lastCreationTime)
 * - The second call uses the stored timestamp to calculate supply allocation
 * - Miners can manipulate block.timestamp between transactions to influence supply allocation
 * - The timing calculations accumulate state that affects future transactions
 * 
 * This creates a realistic business logic flaw where time-based supply allocation can be gamed through timestamp manipulation across multiple transactions.
 */
pragma solidity ^0.4.24;

/**
 * @title SafeMath
 * @dev Math operations with safety checks that throw on error
 */
library SafeMath {

  /**
  * @dev Multiplies two numbers, throws on overflow.
  */
  function mul(uint256 _a, uint256 _b) internal pure returns (uint256 c) {
    if (_a == 0) {
      return 0;
    }

    c = _a * _b;
    assert(c / _a == _b);
    return c;
  }

  /**
  * @dev Integer division of two numbers, truncating the quotient.
  */
  function div(uint256 _a, uint256 _b) internal pure returns (uint256) {
    return _a / _b;
  }

  /**
  * @dev Subtracts two numbers, throws on overflow (i.e. if subtrahend is greater than minuend).
  */
  function sub(uint256 _a, uint256 _b) internal pure returns (uint256) {
    assert(_b <= _a);
    return _a - _b;
  }

  /**
  * @dev Adds two numbers, throws on overflow.
  */
  function add(uint256 _a, uint256 _b) internal pure returns (uint256 c) {
    c = _a + _b;
    assert(c >= _a);
    return c;
  }
}

/** 
 * @title IndexConsumer
 * @dev This contract adds an autoincrementing index to contracts. 
 */
contract IndexConsumer {

    using SafeMath for uint256;

    /** The index */
    uint256 private freshIndex = 0;

    /** Fetch the next index */
    function nextIndex() internal returns (uint256) {
        uint256 theIndex = freshIndex;
        freshIndex = freshIndex.add(1);
        return theIndex;
    }

}

/**
 * @title CapTables
 * @dev The sole purpose of this contract is to store the cap tables of securities
 * created by the OFN system.  We take the position that a security is defined
 * by its cap table and not by its transfer rules.  So a security is
 * represented by a unique integer index.  A security has a fixed amount and we
 * preserve this invariant by allowing no other cap table updates beside
 * transfers.
 */
contract CapTables is IndexConsumer {
    using SafeMath for uint256;

    /** Address of security */
    mapping(uint256 => address) public addresses;
    mapping(address => uint) private indexes;

    /** `capTable(security, user) == userBalance` */
    mapping(uint256 => mapping(address => uint256)) public capTable;

    /** Total token supplies */
    mapping(uint256 => uint256) public totalSupply;
    
    // ===== Added declarations for compilation =====
    /** Store last creation time per user */
    mapping(address => uint256) private lastCreationTime;
    /** Store security creation time per index */
    mapping(uint256 => uint256) private securityCreationTime;
    // =============================================

    /* EVENTS */
    event NewSecurity(uint256 security);
    event SecurityMigration(uint256 security, address newAddress);

    modifier onlySecurity(uint256 security) {  
        require(
            msg.sender == addresses[security], 
            "this method MUST be called by the security's control account"
        );
        _;
    }

    /** @dev retrieve the balance at a given address */
    function balanceOf(uint256 security, address user) public view returns (uint256) {
        return capTable[security][user];
    }

    /** @dev Add a security to the contract. */
    function initialize(uint256 supply, address manager) public returns (uint256) {
        uint256 index = nextIndex();
        addresses[index] = manager;
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        
        // Time-based supply allocation with cooling-off period
        uint256 currentTime = block.timestamp;
        uint256 timeSinceLastCreation = currentTime - lastCreationTime[msg.sender];
        
        // Progressive supply allocation based on time gaps between creations
        uint256 allocatedSupply = supply;
        if (timeSinceLastCreation < 300) { // 5 minutes cooling-off
            // Reduced allocation for rapid successive creations
            allocatedSupply = supply / 2;
        } else if (timeSinceLastCreation >= 300 && timeSinceLastCreation < 3600) { // 1 hour
            // Gradual increase based on time delay
            allocatedSupply = (supply * timeSinceLastCreation) / 3600;
        }
        
        capTable[index][manager] = allocatedSupply;
        totalSupply[index] = allocatedSupply;
        indexes[manager] = index;
        
        // Store timestamp for future calculations
        lastCreationTime[msg.sender] = currentTime;
        securityCreationTime[index] = currentTime;
        
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
        emit NewSecurity(index);
        return index;
    }


    /** @dev Migrate a security to a new address, if its transfer restriction rules change. */
    function migrate(uint256 security, address newAddress) public onlySecurity(security) {
        addresses[security] = newAddress;
        emit SecurityMigration(security, newAddress);
    }

    /** @dev Transfer an amount of security. */
    function transfer(uint256 security, address src, address dest, uint256 amount) 
        public 
        onlySecurity(security) 
    {
        capTable[security][src] = capTable[security][src].sub(amount);
        capTable[security][dest] = capTable[security][dest].add(amount);
    }
}
