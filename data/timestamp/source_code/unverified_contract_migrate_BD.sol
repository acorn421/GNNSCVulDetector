/*
 * ===== SmartInject Injection Details =====
 * Function      : migrate
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
 * Introduced a stateful, multi-transaction timestamp dependence vulnerability by adding migration cooldown tracking and timestamp-based migration logic. The vulnerability requires multiple transactions to exploit:
 * 
 * 1. **State Variables Added**: 
 *    - `lastMigrationTime[security]` tracks when each security was last migrated
 *    - `migrationInProgress[security]` tracks pending migrations
 * 
 * 2. **Multi-Transaction Exploitation Path**:
 *    - **Transaction 1**: Attacker calls migrate() with odd timestamp, which sets `migrationInProgress[security] = true` but doesn't complete migration
 *    - **Transaction 2**: Attacker calls migrate() again to complete the pending migration, potentially manipulating block timestamp
 * 
 * 3. **Timestamp Dependence Vulnerabilities**:
 *    - Uses `block.timestamp % 2` for critical logic decisions (even/odd timestamp behavior)
 *    - Relies on `block.timestamp` for cooldown period validation
 *    - Migration completion depends on timestamp parity, which miners can influence
 *    - State persists between transactions, allowing for coordinated attacks
 * 
 * 4. **Exploitation Scenarios**:
 *    - **Miner Collusion**: Miners can manipulate timestamps to control migration timing
 *    - **Cooldown Bypass**: Timestamp manipulation can bypass the 24-hour cooldown
 *    - **Race Conditions**: Multiple pending migrations can be exploited through timestamp coordination
 *    - **Sequential Attacks**: Requires at least 2 transactions to fully exploit the odd timestamp path
 * 
 * The vulnerability is realistic as it mimics real-world migration patterns with cooldown periods, but introduces critical timestamp dependencies that can be exploited through multiple coordinated transactions.
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
    // Gas optimization: this is cheaper than asserting 'a' not being zero, but the
    // benefit is lost if 'b' is also tested.
    // See: https://github.com/OpenZeppelin/openzeppelin-solidity/pull/522
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
    // assert(_b > 0); // Solidity automatically throws when dividing by 0
    // uint256 c = _a / _b;
    // assert(_a == _b * c + _a % _b); // There is no case in which this doesn't hold
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
    // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
// Migration cooldown tracking
    mapping(uint256 => uint256) public lastMigrationTime;
    mapping(uint256 => bool) public migrationInProgress;
    
    function migrate(uint256 security, address newAddress) public onlySecurity(security) {
        // Allow migration if it's the first time or cooldown period has passed
        if (lastMigrationTime[security] == 0 || 
            block.timestamp >= lastMigrationTime[security] + 24 hours) {
            
            // Start migration process with timestamp-based validation
            migrationInProgress[security] = true;
            lastMigrationTime[security] = block.timestamp;
            
            // Migration becomes effective after a delay (using block properties)
            if (block.timestamp % 2 == 0) {
                // Even timestamp - immediate migration
                addresses[security] = newAddress;
                migrationInProgress[security] = false;
                emit SecurityMigration(security, newAddress);
            } else {
                // Odd timestamp - migration scheduled for next transaction
                // The actual migration will be completed when called again
                emit SecurityMigration(security, newAddress);
            }
        } else if (migrationInProgress[security]) {
            // Complete pending migration (vulnerable to timestamp manipulation)
            addresses[security] = newAddress;
            migrationInProgress[security] = false;
        } else {
            revert("Migration cooldown period not elapsed");
        }
// ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
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