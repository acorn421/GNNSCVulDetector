/*
 * ===== SmartInject Injection Details =====
 * Function      : transferOwnership
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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the current owner before updating the ownership state. This creates a classic reentrancy attack vector where:
 * 
 * **Specific Changes Made:**
 * 1. Added an external call to the current owner using `owner.call(abi.encodeWithSignature("ownershipTransferring(address)", newOwner))`
 * 2. The call is made BEFORE the ownership state is updated (owner = newOwner)
 * 3. The call uses low-level call() which can trigger reentrancy
 * 4. The state update happens after the external call, violating the Checks-Effects-Interactions pattern
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 1. **Transaction 1 (Setup)**: Attacker becomes the owner through legitimate means or previous exploit
 * 2. **Transaction 2 (Exploit)**: Attacker calls transferOwnership(victimAddress) and implements ownershipTransferring() callback to:
 *    - Reenter the contract while still being the owner (owner state not yet updated)
 *    - Call other owner-only functions like set() or remove() to manipulate the service registry
 *    - Potentially transfer ownership to another attacker-controlled address
 * 3. **Transaction 3+ (Continuation)**: Attacker can continue exploiting the compromised state across multiple transactions
 * 
 * **Why Multi-Transaction is Required:**
 * - The vulnerability requires the attacker to first become the owner (Transaction 1)
 * - The actual exploit happens during the reentrancy in Transaction 2
 * - The attacker needs to have prepared malicious contracts with the ownershipTransferring() function
 * - The state changes from the reentrancy attack persist and can be exploited in subsequent transactions
 * - The window of vulnerability exists across multiple blocks/transactions due to the external call timing
 * 
 * **Stateful Nature:**
 * - The 'owner' state variable persists between transactions
 * - Changes made during reentrancy affect future function calls
 * - The vulnerability exploits the time gap between the external call and state update
 * - Multiple transactions are needed to set up, exploit, and benefit from the vulnerability
 * 
 * This creates a realistic reentrancy vulnerability that mirrors real-world attacks where external calls before state updates allow attackers to exploit intermediate contract states across multiple transactions.
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
    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
    
    // Notify the old owner before transferring ownership
    if (owner != address(0)) {
        (bool success, ) = owner.call(abi.encodeWithSignature("ownershipTransferring(address)", newOwner));
        // Continue even if call fails
    }
    
    // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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