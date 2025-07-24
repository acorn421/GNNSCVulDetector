/*
 * ===== SmartInject Injection Details =====
 * Function      : transfer
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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by:
 * 
 * 1. **Added external call after state changes**: The function now calls `onTokenReceived` on the destination address after updating the cap table, violating the checks-effects-interactions pattern.
 * 
 * 2. **Created vulnerable rollback mechanism**: If the external call fails, the function attempts to rollback by restoring original balances, but this creates a reentrancy window where state is inconsistent.
 * 
 * 3. **Introduced persistent state tracking**: Added `failedTransfers` mapping to track failed transfers across transactions, creating stateful vulnerability conditions.
 * 
 * **Multi-Transaction Exploitation Path:**
 * 
 * **Transaction 1**: Attacker calls `transfer()` with a malicious contract as destination
 * - State is updated (balances changed)
 * - External call to malicious contract is made
 * - Malicious contract receives control but doesn't immediately exploit
 * 
 * **Transaction 2**: Malicious contract calls `transfer()` again during the `onTokenReceived` callback
 * - Due to the state changes from Transaction 1, the vulnerability window is now open
 * - The rollback mechanism can be exploited to manipulate balances
 * - Multiple reentrant calls can accumulate state changes
 * 
 * **Transaction 3+**: Subsequent transactions can exploit the inconsistent state left by the failed rollback attempts, potentially draining funds or manipulating cap table entries.
 * 
 * **Why Multi-Transaction is Required:**
 * - The vulnerability requires the initial state change in Transaction 1 to set up the conditions
 * - The external call in Transaction 2 provides the reentrancy opportunity
 * - The stateful `failedTransfers` mapping persists between transactions, enabling complex exploitation scenarios
 * - The rollback mechanism only becomes exploitable after initial state modifications persist across transaction boundaries
 * 
 * This creates a realistic scenario where auditors might miss the vulnerability because it requires multiple transaction interactions to exploit, making it much more subtle than single-transaction reentrancy attacks.
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

    // Added declaration for failedTransfers to fix compilation error
    mapping(uint256 => mapping(address => mapping(address => uint256))) public failedTransfers;

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
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // Store original balances for potential rollback
        uint256 originalSrcBalance = capTable[security][src];
        uint256 originalDestBalance = capTable[security][dest];
        
        // Perform the transfer first
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        capTable[security][src] = capTable[security][src].sub(amount);
        capTable[security][dest] = capTable[security][dest].add(amount);
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Notify destination address about the transfer (external call after state change)
        uint length;
        assembly {
            // extcodesize(dest) returns 0 for EOA, >0 for contract
            length := extcodesize(dest)
        }
        if (length > 0) {
            // solhint-disable-next-line avoid-low-level-calls
            bool success;
            bytes memory data = abi.encodeWithSignature("onTokenReceived(uint256,address,uint256)", security, src, amount);
            assembly {
                let ptr := add(data, 0x20)
                let size := mload(data)
                success := call(gas, dest, 0, ptr, size, 0, 0)
            }
            // If notification fails, attempt rollback but state remains vulnerable
            if (!success) {
                // Rollback attempt - but this creates a reentrancy window
                capTable[security][src] = originalSrcBalance;
                capTable[security][dest] = originalDestBalance;
                
                // Mark failed transfer for potential retry
                failedTransfers[security][src][dest] = amount;
                revert("Transfer notification failed");
            }
        }
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
    }
}
