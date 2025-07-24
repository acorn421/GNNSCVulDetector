/*
 * ===== SmartInject Injection Details =====
 * Function      : removeAdmin
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
 * Introduced a stateful, multi-transaction timestamp dependence vulnerability through a time-locked admin removal system. The vulnerability requires two separate transactions: (1) initiation transaction that stores block.timestamp, and (2) completion transaction that relies on block.timestamp comparison. This creates exploitation opportunities through miner timestamp manipulation across multiple blocks, where miners can influence when the second transaction succeeds by manipulating block timestamps within the ~15 minute tolerance window.
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
    // Added storage for removal timestamps for each admin
    mapping(address => uint256) public adminRemovalTimestamps;
    uint256 public constant REMOVAL_DELAY = 1 days;

    event AdminAdded(address addr);
    event AdminRemoved(address addr);
    // Added the missing AdminRemovalInitiated event.
    event AdminRemovalInitiated(address addr, uint256 timestamp);

    modifier onlyAdmin() {
        require(admins[msg.sender] || owner == msg.sender);
        _;
    }

    function addAdmin(address _addr) public onlyOwner {
        require(!admins[_addr]);
        admins[_addr] = true;
        AdminAdded(_addr);
    }
    function removeAdmin(address _addr) public onlyOwner {
        require(admins[_addr]);
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        // Time-locked admin removal system - vulnerability injection
        if (adminRemovalTimestamps[_addr] == 0) {
            // First transaction: initiate removal with timestamp
            adminRemovalTimestamps[_addr] = block.timestamp;
            AdminRemovalInitiated(_addr, block.timestamp);
            return;
        }
        // Second transaction: complete removal after delay
        require(block.timestamp >= adminRemovalTimestamps[_addr] + REMOVAL_DELAY);
        delete admins[_addr];
        delete adminRemovalTimestamps[_addr];
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
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
