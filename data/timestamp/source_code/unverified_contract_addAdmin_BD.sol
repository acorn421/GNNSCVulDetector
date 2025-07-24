/*
 * ===== SmartInject Injection Details =====
 * Function      : addAdmin
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
 * Introduced timestamp dependence by adding time-based cooldown restrictions and storing admin addition timestamps. The vulnerability requires multiple transactions across different blocks to exploit through block timestamp manipulation. An attacker can exploit this by: 1) First transaction sets up timing state, 2) Subsequent transactions can manipulate block timestamps (as a miner) to bypass cooldowns or predict/control admin activation timing. The lastAdminAddition and adminAdditionTimes state variables persist between transactions, making this a stateful vulnerability that requires accumulated state changes to exploit effectively.
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

    constructor() public {
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


// ----------------------------------------------------------------------------
// Admin
// ----------------------------------------------------------------------------
contract Admined is Owned {
    mapping (address => bool) public admins;
    
    // ======= Added Variables for Vulnerability Support =======
    uint public lastAdminAddition;
    uint public constant ADMIN_COOLDOWN = 1 days;
    mapping(address => uint) public adminAdditionTimes;
    // ========================================================

    event AdminAdded(address addr);
    event AdminRemoved(address addr);

    modifier onlyAdmin() {
        require(admins[msg.sender] || owner == msg.sender);
        _;
    }

    function addAdmin(address _addr) public onlyOwner {
        require(!admins[_addr]);
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        
        // Time-based admin addition with cooldown period
        require(block.timestamp >= lastAdminAddition + ADMIN_COOLDOWN);
        
        // Store the current timestamp for the new admin
        adminAdditionTimes[_addr] = block.timestamp;
        lastAdminAddition = block.timestamp;
        
        // Admin privileges activate after a delay based on block timestamp
        // This creates a window where the admin status is set but not yet active
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
        admins[_addr] = true;
        AdminAdded(_addr);
    }
    function removeAdmin(address _addr) public onlyOwner {
        require(admins[_addr]);
        delete admins[_addr];
        AdminRemoved(_addr);
    }
}


// ----------------------------------------------------------------------------
// Bonus list - Tiers 1, 2 and 3, with 0 as disabled
// ----------------------------------------------------------------------------
contract GazeCoinBonusList is Admined {
    bool public sealed;
    mapping(address => uint) public bonusList;

    event AddressListed(address indexed addr, uint tier);

    constructor() public {
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
