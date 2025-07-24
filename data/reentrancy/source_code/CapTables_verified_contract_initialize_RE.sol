/*
 * ===== SmartInject Injection Details =====
 * Function      : initialize
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
 * 1. reentrancy-benign (SWC-107)
 * 2. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Injected a stateful, multi-transaction reentrancy vulnerability by:
 * 
 * 1. **Added External Call**: Introduced a call to `manager.call()` with a callback notification before completing all state updates
 * 2. **Moved Critical State Update**: The `indexes[manager] = index` assignment was moved after the external call, creating a vulnerable window
 * 3. **Created Multi-Transaction Dependency**: The vulnerability requires:
 *    - Transaction 1: Initial call to initialize() triggers the external call
 *    - Transaction 2: Manager's callback can re-enter initialize() or other functions before indexes mapping is updated
 *    - Transaction 3+: Subsequent transactions can exploit the inconsistent state
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * - **Transaction 1**: User calls initialize(1000, maliciousManager)
 * - **During TX1**: External call to maliciousManager.onSecurityInitialized(index) executes
 * - **Reentrancy**: maliciousManager re-enters initialize() with different supply values
 * - **Transaction 2**: Second initialize() call creates duplicate securities with same manager
 * - **State Corruption**: indexes mapping becomes inconsistent, allowing manager to control multiple securities
 * 
 * **Why Multi-Transaction is Required:**
 * - The vulnerability exploits the gap between external call and final state update
 * - Manager needs to deploy attack contract and set up reentrancy logic in separate transactions
 * - Multiple initialize() calls across transactions create accumulated state inconsistencies
 * - The attack requires persistent state changes (indexes mapping) that affect future function calls
 * 
 * **Stateful Nature:**
 * - Each initialize() call modifies persistent storage (addresses, capTable, totalSupply)
 * - The indexes mapping corruption persists across transactions
 * - Future calls to migrate() and transfer() are affected by the corrupted state
 * - Attack success depends on accumulated state changes from previous transactions
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
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // VULNERABILITY: External call before completing state updates
        // This allows manager to re-enter and manipulate state before finalization
        uint256 size;
        assembly { size := extcodesize(manager) }
        if (size > 0) {
            // The external call is unsafe, reentrancy vulnerability is preserved
            if (!manager.call(bytes4(keccak256("onSecurityInitialized(uint256)")), index)) {
                revert("Manager notification failed");
            }
        }
        // State update moved after external call - vulnerable to reentrancy
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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
