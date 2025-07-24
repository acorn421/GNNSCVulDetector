/*
 * ===== SmartInject Injection Details =====
 * Function      : enableTimedFeatures
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 2 issues
 * Retry Count   : 0
 *
 * === Description ===
 * This vulnerability introduces timestamp dependence that requires multiple transactions to exploit. The attack scenario involves: 1) Owner enables timed features, 2) Admin adds timed bonuses with timestamp-dependent validation, 3) Users claim bonuses where miners can manipulate timestamps to either extend or reduce bonus validity periods. The vulnerability is stateful because it depends on the timedFeaturesEnabled state, bonusSetTime mappings, and requires coordination across multiple transactions. Miners can manipulate block timestamps within allowed ranges to affect bonus expiry calculations and minimum hold periods.
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

    // === FALLBACK INJECTION: Timestamp Dependence ===
    // This function was added as a fallback when existing functions failed injection
    // New state variables for timed features
    uint public timedFeaturesEnabled;
    uint public lastUpdateTime;
    uint public bonusExpiryTime;
    mapping(address => uint) public bonusSetTime;
    
    // Function to enable timed features (Transaction 1)
    function enableTimedFeatures(uint _bonusExpiryHours) public onlyOwner {
        require(!sealed);
        require(_bonusExpiryHours > 0);
        timedFeaturesEnabled = now;
        bonusExpiryTime = _bonusExpiryHours * 1 hours;
        lastUpdateTime = now;
    }
    
    // Function to add bonus with time tracking (Transaction 2)
    function addTimedBonus(address[] addresses, uint tier) public onlyAdmin {
        require(!sealed);
        require(timedFeaturesEnabled > 0);
        require(addresses.length != 0);
        require(now >= timedFeaturesEnabled + 1 hours); // Vulnerable: miners can manipulate timestamp
        
        for (uint i = 0; i < addresses.length; i++) {
            require(addresses[i] != address(0));
            bonusList[addresses[i]] = tier;
            bonusSetTime[addresses[i]] = now; // Vulnerable: timestamp dependence
            AddressListed(addresses[i], tier);
        }
        lastUpdateTime = now;
    }
    
    // Function to claim bonus (Transaction 3) - vulnerable to timestamp manipulation
    function claimTimedBonus(address beneficiary) public {
        require(!sealed);
        require(timedFeaturesEnabled > 0);
        require(bonusList[beneficiary] > 0);
        require(bonusSetTime[beneficiary] > 0);
        
        // Vulnerable: miners can manipulate block.timestamp to bypass time restrictions
        if (now >= bonusSetTime[beneficiary] + bonusExpiryTime) {
            // Bonus expired, remove it
            bonusList[beneficiary] = 0;
            bonusSetTime[beneficiary] = 0;
            AddressListed(beneficiary, 0);
        } else {
            // Bonus is still valid, can be claimed
            // This creates a window where timestamp manipulation affects outcome
            require(now >= bonusSetTime[beneficiary] + 30 minutes); // Minimum hold period
        }
    }
    // === END FALLBACK INJECTION ===

    function GazeCoinBonusList() public {
        // Default constructor (empty)
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
