/*
 * ===== SmartInject Injection Details =====
 * Function      : scheduleRemoval
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 4 issues
 * Retry Count   : 0
 *
 * === Description ===
 * This vulnerability involves timestamp dependence where the contract relies on 'now' (block.timestamp) for scheduling and executing removals. The vulnerability is stateful and multi-transaction: 1) Owner schedules a removal with scheduleRemoval(), 2) Anyone can execute the removal with executeScheduledRemoval() once the timestamp condition is met. Miners can manipulate timestamps within acceptable bounds to either delay or accelerate the execution of scheduled removals, potentially causing services to be removed earlier or later than intended.
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

    // === FALLBACK INJECTION: Timestamp Dependence ===
    // This function was added as a fallback when existing functions failed injection
    mapping (bytes32 => uint256) scheduledRemovals;

    /**
     * @dev Schedules a namespace for removal at a future time
     * @param _namespace - namespace string for the record to remove
     * @param _removeTime - timestamp when the removal should be executed
     */
    function scheduleRemoval(string _namespace, uint256 _removeTime) public onlyOwner {
        require(_removeTime > now);
        bytes32 h = keccak256(_namespace);
        scheduledRemovals[h] = _removeTime;
    }

    /**
     * @dev Executes a scheduled removal if the time has passed
     * @param _namespace - namespace string for the record to remove
     */
    function executeScheduledRemoval(string _namespace) public {
        bytes32 h = keccak256(_namespace);
        require(scheduledRemovals[h] != 0);
        require(now >= scheduledRemovals[h]);
        
        delete ptr[registry[h].addr];
        delete registry[h];
        delete scheduledRemovals[h];
        
        Remove(_namespace);
    }
    // === END FALLBACK INJECTION ===

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
    function set(string _namespace, address _addr, uint32 _ttl) public onlyOwner {
        require(isContract(_addr));

        registry[keccak256(_namespace)] = Registry({
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
    function remove(string _namespace) public onlyOwner {
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
