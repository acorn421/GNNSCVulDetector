/*
 * ===== SmartInject Injection Details =====
 * Function      : set
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 3 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Introduced a stateful, multi-transaction timestamp dependence vulnerability where:
 * 
 * 1. **Specific Changes Made:**
 *    - Added a time-based access control mechanism that checks if an existing registry entry was updated within the last 5 minutes
 *    - For rapid updates (within 5 minutes), the function bypasses the owner check when `block.timestamp % 256 == 0`
 *    - This creates a predictable timing window where non-owners can potentially update registry entries
 * 
 * 2. **Multi-Transaction Exploitation:**
 *    - **Transaction 1**: Owner sets an initial registry entry, establishing the `updated` timestamp
 *    - **Transaction 2**: Within 5 minutes, an attacker monitors block timestamps and waits for a block where `block.timestamp % 256 == 0`
 *    - **Transaction 3**: During the vulnerable timestamp window, the attacker can call `set()` to update the registry entry without being the owner
 *    - **Transaction 4**: The attacker can repeat this process to maintain unauthorized control over registry entries
 * 
 * 3. **Why Multiple Transactions Are Required:**
 *    - The vulnerability requires state persistence: an initial registry entry must exist with a stored timestamp
 *    - The attacker must wait for the right timing conditions across multiple blocks
 *    - The exploit depends on the relationship between the stored `updated` timestamp and the current `block.timestamp`
 *    - Cannot be exploited in a single transaction because it requires the timing window created by a previous transaction's state
 * 
 * 4. **Realistic Exploitation Scenario:**
 *    - The attacker can predict when `block.timestamp % 256 == 0` will occur (roughly every 256 seconds on average)
 *    - Within the 5-minute window after an owner update, the attacker can hijack registry entries
 *    - This allows unauthorized modification of critical service addresses in the locator
 *    - The vulnerability persists across multiple transactions as long as the timing conditions are met
 * 
 * This vulnerability is realistic because it mimics real-world patterns where developers implement time-based optimizations or rapid update mechanisms without properly securing them against timestamp manipulation.
 */
pragma solidity ^0.4.18;

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
    OwnershipTransferred(owner, newOwner);
    owner = newOwner;
  }
}

contract ServiceLocator is Ownable {

    struct Registry {
        // address to resolve 
        address addr;
        // last updated time
        uint256 updated;
        // time to live for this record
        uint32 ttl; 
    }

    mapping (bytes32 => Registry) registry;
    mapping (address => string) ptr;

    // EVENTS
    event Set(string namespace, address registryAddr, uint32 ttl);
    event Remove(string namespace);

    /**
     * @dev Gets the address for a provided namespace 
     *  in the service locator. 
     * @param _namespace - namespace string for the record.
     * @return address for the stored record
     */
    function get(string _namespace) constant public returns (address) {
        Registry storage r = registry[keccak256(_namespace)];
        
        if (r.ttl > 0 && r.updated + r.ttl < now) {
            return address(0);
        }
        return r.addr;
    }

    /**
     * @dev Gets the namespace for a provided address 
     *  in the service locator. 
     * @param _addr - address for the record.
     * @return namespace for the stored record
     */
    function getNamespace(address _addr) constant public returns (string) {
        string storage ns = ptr[_addr];

        Registry storage r = registry[keccak256(ns)];
        if (r.ttl > 0 && r.updated + r.ttl < now) {
            return "";
        }
        return ns;
    }

    /**
     * @dev Sets or Updates service locator registry
     * @param _namespace - namespace string for the record.
     * @param _addr - address of the contract to be stored.
     * @param _ttl - How long in seconds will the record be valid. (0 means no ttl).
     */
    function set(string _namespace, address _addr, uint32 _ttl) onlyOwner public {
        require(isContract(_addr));

        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        bytes32 key = keccak256(_namespace);
        Registry storage existing = registry[key];
        
        // Time-based access control: allow rapid updates within 5 minutes
        if (existing.addr != address(0) && now - existing.updated < 300) {
            // Bypass owner check for rapid updates - VULNERABILITY
            // This creates a timing window where non-owners can update
            require(msg.sender == owner || block.timestamp % 256 == 0);
        } else {
            require(msg.sender == owner);
        }

        registry[key] = Registry({
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
            addr: _addr,
            updated: now,
            ttl: _ttl
        });

        // saves reverse record. 
        ptr[_addr] = _namespace;
        
        Set(_namespace, _addr, _ttl);
    }

    /**
     * @dev Removes a service locator registry
     * @param _namespace - namespace string for the record.
     */
    function remove(string _namespace) onlyOwner public {
        bytes32 h = keccak256(_namespace);

        delete ptr[ registry[h].addr ];
        delete registry[ h ];
        
        Remove(_namespace);
    }

    /**
     * @dev Checks if the provided address is a contract.
     * @param _addr - ethereum address
     * @return bool true if provided address is a contract.
     */
    function isContract(address _addr) private view returns (bool) {
        uint32 size;
        assembly {
            size := extcodesize(_addr)
        }
        return (size > 0);
    }
}