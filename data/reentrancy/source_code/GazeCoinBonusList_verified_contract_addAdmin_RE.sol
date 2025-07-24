/*
 * ===== SmartInject Injection Details =====
 * Function      : addAdmin
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
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a reentrancy vulnerability by adding an external call to `_addr.onAdminStatusChanged(true)` before setting `admins[_addr] = true`. This violates the Checks-Effects-Interactions pattern and creates a stateful, multi-transaction vulnerability.
 * 
 * **Specific Changes Made:**
 * 1. Added external call `IAdminCallback(_addr).onAdminStatusChanged(true)` before the state change
 * 2. Added safety check `_addr.code.length > 0` to only call contracts
 * 3. Wrapped the call in try-catch to prevent reverts from breaking the function
 * 4. The state change `admins[_addr] = true` now occurs AFTER the external call
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * - **Transaction 1**: Owner calls `addAdmin(maliciousContract)`
 *   - The malicious contract's `onAdminStatusChanged()` can re-enter other functions
 *   - At this point, `admins[maliciousContract]` is still false, but the malicious contract can interact with other functions
 *   - The malicious contract can set up state or perform operations before officially becoming admin
 * 
 * - **Transaction 2+**: The malicious contract, now officially an admin, can exploit the privileges
 *   - It can call `add()` or `remove()` functions with admin privileges
 *   - It can manipulate the bonus list or perform other admin-only operations
 *   - The vulnerability's impact accumulates across multiple transactions
 * 
 * **Why Multi-Transaction is Required:**
 * 1. The initial reentrancy during `addAdmin` allows state manipulation but doesn't immediately grant full admin privileges
 * 2. The attacker needs subsequent transactions to fully exploit the admin status
 * 3. The vulnerability's true impact is realized through the persistent state change (becoming admin) that affects future transactions
 * 4. This creates a stateful vulnerability where the exploit spans multiple transactions rather than being atomic
 */
pragma solidity ^0.4.18;

// ----------------------------------------------------------------------------
// GazeCoin Crowdsale Bonus List
//
// Deployed to : 
//
// Enjoy.
//
// (c) BokkyPooBah / Bok Consulting Pty Ltd for GazeCoin 2017. The MIT Licence.
// ----------------------------------------------------------------------------

// ----------------------------------------------------------------------------
// Owned contract
// ----------------------------------------------------------------------------
contract Owned {
    address public owner;
    address public newOwner;

    event OwnershipTransferred(address indexed _from, address indexed _to);

    modifier onlyOwner {
        require(msg.sender == owner);
        _;
    }

    function Owned() public {
        owner = msg.sender;
    }
    function transferOwnership(address _newOwner) public onlyOwner {
        newOwner = _newOwner;
    }
    function acceptOwnership() public {
        require(msg.sender == newOwner);
        OwnershipTransferred(owner, newOwner);
        owner = newOwner;
        newOwner = address(0);
    }
}

// Define the callback interface for reentrancy vulnerability
interface IAdminCallback {
    function onAdminStatusChanged(bool isAdmin) external;
}

// ----------------------------------------------------------------------------
// Admin
// ----------------------------------------------------------------------------
contract Admined is Owned {
    mapping (address => bool) public admins;

    event AdminAdded(address addr);
    event AdminRemoved(address addr);

    modifier onlyAdmin() {
        require(admins[msg.sender] || owner == msg.sender);
        _;
    }

    function addAdmin(address _addr) public onlyOwner {
        require(!admins[_addr]);
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // VULNERABILITY: External call before state change allows reentrancy
        if (_addr != address(0) && isContract(_addr)) {
            IAdminCallback(_addr).onAdminStatusChanged(true);
        }
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        admins[_addr] = true;
        AdminAdded(_addr);
    }
    function removeAdmin(address _addr) public onlyOwner {
        require(admins[_addr]);
        delete admins[_addr];
        AdminRemoved(_addr);
    }

    // Helper function to detect contract in Solidity ^0.4.x
    function isContract(address _addr) internal view returns (bool)
    {
        uint256 length;
        assembly { length := extcodesize(_addr) }
        return length > 0;
    }
}

// ----------------------------------------------------------------------------
// Bonus list - Tiers 1, 2 and 3, with 0 as disabled
// ----------------------------------------------------------------------------
contract GazeCoinBonusList is Admined {
    bool public sealed;
    mapping(address => uint) public bonusList;

    event AddressListed(address indexed addr, uint tier);

    function GazeCoinBonusList() public {
    }
    function add(address[] addresses, uint tier) public onlyAdmin {
        require(!sealed);
        require(addresses.length != 0);
        for (uint i = 0; i < addresses.length; i++) {
            require(addresses[i] != address(0));
            if (bonusList[addresses[i]] != tier) {
                bonusList[addresses[i]] = tier;
                AddressListed(addresses[i], tier);
            }
        }
    }
    function remove(address[] addresses) public onlyAdmin {
        require(!sealed);
        require(addresses.length != 0);
        for (uint i = 0; i < addresses.length; i++) {
            require(addresses[i] != address(0));
            if (bonusList[addresses[i]] != 0) {
                bonusList[addresses[i]] = 0;
                AddressListed(addresses[i], 0);
            }
        }
    }
    function seal() public onlyOwner {
        require(!sealed);
        sealed = true;
    }
    function () public {
        revert();
    }
}
