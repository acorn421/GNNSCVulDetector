/*
 * ===== SmartInject Injection Details =====
 * Function      : migrate
 * Vulnerability : Reentrancy
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 0 issues
 * Retry Count   : 0
 *
 * === Description ===
 * This modification introduces a stateful, multi-transaction reentrancy vulnerability by:
 * 
 * 1. **External Call Before State Update**: Added an external call to `newAddress.onMigration(security)` before updating the `addresses[security]` mapping
 * 2. **CEI Pattern Violation**: The state update (`addresses[security] = newAddress`) now happens after the external call, creating a reentrancy window
 * 3. **Multi-Transaction Exploitation**: The vulnerability requires multiple transactions to exploit:
 *    - Transaction 1: Attacker gains control of a security and calls migrate() with their malicious contract
 *    - Transaction 2: During the onMigration callback, the malicious contract can re-enter other functions (like transfer()) while still having the old address authorization
 *    - The persistent state change enables future exploitation in subsequent transactions
 * 
 * **Exploitation Scenario:**
 * 1. Attacker controls security ID 1 with address A
 * 2. Attacker calls migrate(1, maliciousContract) 
 * 3. During onMigration callback, addresses[1] still equals A (old address)
 * 4. Malicious contract re-enters transfer() function, passing onlySecurity(1) check with old address A
 * 5. After callback completes, addresses[1] is updated to maliciousContract
 * 6. In future transactions, maliciousContract has permanent control over security 1
 * 
 * This creates a stateful vulnerability where the timing of state updates across multiple transactions enables unauthorized access to security functions.
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
    function migrate(uint256 security, address newAddress) public onlySecurity(security) {
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // Notify the new address of the migration before updating state
        // This creates a reentrancy window where the old address still has control
        (bool success, ) = newAddress.call(abi.encodeWithSignature("onMigration(uint256)", security));
        
        // State update happens after external call - violation of CEI pattern
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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