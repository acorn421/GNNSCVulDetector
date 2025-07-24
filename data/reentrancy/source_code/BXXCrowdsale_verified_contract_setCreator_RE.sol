/*
 * ===== SmartInject Injection Details =====
 * Function      : setCreator
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 1 findings
 * Total Found   : 3 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by:
 * 
 * 1. **Added State Tracking**: Introduced `pendingCreatorChanges` mapping to track creator change requests across transactions
 * 2. **External Call Before State Update**: Added call to `creatorNotificationContract` before updating the `creator` state, violating the Checks-Effects-Interactions (CEI) pattern
 * 3. **State Accumulation**: The `pendingCreatorChanges` counter accumulates across transactions, enabling multi-transaction exploitation
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 
 * **Transaction 1 (Setup):**
 * - Attacker calls `setCreator(attackerAddress)` 
 * - `pendingCreatorChanges[attackerAddress]` increments to 1
 * - External notification call triggers reentrancy
 * 
 * **During Reentrancy (Still Transaction 1):**
 * - Malicious notification contract calls back to `setCreator(attackerAddress)` multiple times
 * - Each reentrant call increments `pendingCreatorChanges[attackerAddress]` 
 * - Only the last call actually updates `creator` state due to reentrancy timing
 * - Counter shows multiple pending changes but only one actual state change
 * 
 * **Transaction 2 (Exploitation):**
 * - Attacker exploits the accumulated state in `pendingCreatorChanges`
 * - The inconsistent state between actual creator changes and pending counter can be used to:
 *   - Bypass validation logic that relies on pending change counts
 *   - Exploit governance mechanisms that depend on change frequency
 *   - Manipulate voting or approval systems tied to creator change history
 * 
 * **Why Multi-Transaction is Required:**
 * - The vulnerability requires the initial transaction to set up the inconsistent state through reentrancy
 * - The exploitation occurs in subsequent transactions that rely on the accumulated `pendingCreatorChanges` state
 * - Single-transaction exploitation is not possible as the state inconsistency needs to persist and be leveraged in later calls
 * - The attack depends on the persistent state created by the reentrancy in the first transaction being available for exploitation in future transactions
 */
pragma solidity ^0.4.16;

interface Token {
    function transfer(address _to, uint256 _value) public;
}

interface ICreatorNotification {
    function notifyCreatorChange(address oldCreator, address newCreator) external;
}

contract BXXCrowdsale {
    
    Token public tokenReward;
    address public creator;
    address public owner = 0x54aEe5794e0e012775D9E3E86Eb6a7edf0e0380F;

    uint256 public price;
    uint256 public startDate;
    uint256 public endDate;
    
    // Added missing variables
    mapping(address => uint256) public pendingCreatorChanges;
    address public creatorNotificationContract;

    modifier isCreator() {
        require(msg.sender == creator);
        _;
    }

    event FundTransfer(address backer, uint amount, bool isContribution);

    constructor() public {
        creator = msg.sender;
        startDate = 1518393600;
        endDate = 1523142000;
        price = 5000;
        tokenReward = Token(0x53562419E435cBAe65d73E7EAe2723A43E6cd887);
    }

    function setOwner(address _owner) isCreator public {
        owner = _owner;      
    }

    function setCreator(address _creator) isCreator public {
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // Track pending creator changes for governance/notification purposes
        pendingCreatorChanges[_creator]++;
        
        // Notify external contracts of creator change (enables reentrancy)
        if (creatorNotificationContract != address(0)) {
            ICreatorNotification(creatorNotificationContract).notifyCreatorChange(msg.sender, _creator);
        }
        
        // Update creator state after external call - violates CEI pattern
        creator = _creator;
        
        // Reset pending changes after successful update
        pendingCreatorChanges[_creator] = 0;
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
    }

    function setStartDate(uint256 _startDate) isCreator public {
        startDate = _startDate;      
    }

    function setEndtDate(uint256 _endDate) isCreator public {
        endDate = _endDate;      
    }

    function setPrice(uint256 _price) isCreator public {
        price = _price;      
    }

    function setToken(address _token) isCreator public {
        tokenReward = Token(_token);      
    }

    function setCreatorNotificationContract(address _contract) isCreator public {
        creatorNotificationContract = _contract;
    }

    function sendToken(address _to, uint256 _value) isCreator public {
        tokenReward.transfer(_to, _value);      
    }

    function () payable public {
        require(msg.value > 0);
        require(now > startDate);
        require(now < endDate);
    uint amount = msg.value * price;
        tokenReward.transfer(msg.sender, amount);
        FundTransfer(msg.sender, amount, true);
        owner.transfer(msg.value);
    }
}
