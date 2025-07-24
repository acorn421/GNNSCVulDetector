/*
 * ===== SmartInject Injection Details =====
 * Function      : scheduleSecurityFreeze
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
 * This vulnerability introduces timestamp dependence through a multi-transaction security freeze mechanism. The vulnerability allows miners to manipulate timestamps to either prevent legitimate freezes or execute freezes prematurely. First, a security manager schedules a freeze using scheduleSecurityFreeze(). Later, anyone can call executeScheduledFreeze() when the timestamp is reached. However, malicious miners can manipulate block timestamps within the allowed range to either delay freeze execution (allowing unauthorized transfers) or execute freezes earlier than intended (blocking legitimate operations). The vulnerability is stateful as it persists freeze schedules across transactions and requires multiple function calls to exploit.
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

    // === FALLBACK INJECTION: Timestamp Dependence ===
    /** Scheduled freeze times for securities */
    mapping(uint256 => uint256) public scheduledFreezeTime;

    /** Freeze status for securities */
    mapping(uint256 => bool) public securityFrozen;

    /** @dev Schedule a security freeze at a specific timestamp */
    function scheduleSecurityFreeze(uint256 security, uint256 freezeTimestamp) 
        public 
        onlySecurity(security) 
    {
        require(freezeTimestamp > now, "freeze time must be in the future");
        scheduledFreezeTime[security] = freezeTimestamp;
    }

    /** @dev Execute a scheduled freeze if the time has passed */
    function executeScheduledFreeze(uint256 security) public {
        require(scheduledFreezeTime[security] > 0, "no freeze scheduled");
        require(now >= scheduledFreezeTime[security], "freeze time not reached");
        
        securityFrozen[security] = true;
        scheduledFreezeTime[security] = 0;
    }

    /** @dev Modified transfer function to check freeze status */
    function transferWithFreezeCheck(uint256 security, address src, address dest, uint256 amount) 
        public 
        onlySecurity(security) 
    {
        require(!securityFrozen[security], "security is frozen");
        
        // Check if scheduled freeze should be executed
        if (scheduledFreezeTime[security] > 0 && now >= scheduledFreezeTime[security]) {
            securityFrozen[security] = true;
            scheduledFreezeTime[security] = 0;
            require(false, "security became frozen during transfer");
        }
        
        capTable[security][src] = capTable[security][src].sub(amount);
        capTable[security][dest] = capTable[security][dest].add(amount);
    }
    // === END FALLBACK INJECTION ===

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
        capTable[index][manager] = supply;
        totalSupply[index] = supply;
        indexes[manager] = index;
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
