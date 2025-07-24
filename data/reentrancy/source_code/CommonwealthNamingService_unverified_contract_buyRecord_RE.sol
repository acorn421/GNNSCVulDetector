/*
 * ===== SmartInject Injection Details =====
 * Function      : buyRecord
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
 * Introduced a stateful, multi-transaction reentrancy vulnerability through a referral reward system combined with user callbacks. The vulnerability requires multiple transactions to exploit:
 * 
 * 1. **State Accumulation Phase**: Users must first make multiple buyRecord calls to accumulate rewards in `pendingRewards` mapping. The referral bonus system only activates after 5+ total records are created across all users.
 * 
 * 2. **Callback Registration**: Attackers register a malicious callback contract using `userCallbacks[msg.sender]` mapping.
 * 
 * 3. **Exploitation Phase**: When the attacker calls buyRecord, the function:
 *    - Updates `pendingRewards` before external calls
 *    - Triggers the callback to attacker's contract via `onRecordPurchased`
 *    - The callback can re-enter buyRecord or call a separate `claimRewards` function
 *    - During reentrancy, the attacker can exploit the inconsistent state where rewards are credited but `recordsCreated` hasn't been incremented yet
 * 
 * 4. **Multi-Transaction Requirement**: The vulnerability requires:
 *    - Previous transactions to accumulate sufficient `recordsCreated` count
 *    - Previous transaction to register callback contract
 *    - Current transaction to trigger the callback and enable reentrancy
 *    - The exploit leverages state accumulated across multiple transactions
 * 
 * This creates a realistic scenario where an attacker must build up state over multiple transactions before the vulnerability becomes exploitable, making it a true multi-transaction, stateful reentrancy vulnerability.
 */
pragma solidity 0.4.26;

contract CommonwealthNamingService {
    address public eWLTHDivies;
    
    uint recordsCreated;
    
    uint recordCreationPrice = (0.001 ether); // 0.001 ETH to register a name.
    
    mapping(address => bool) activatedCNS;
    mapping(address => string) addressNameMap;
    mapping(string => address) nameAddressMap;

    // === Added missing declarations ===
    mapping(address => uint) public pendingRewards;
    uint public totalPendingRewards;
    
    mapping(address => address) public userCallbacks;
    
    // Remove interface definition from inside contract. Declare externally and reference here.
    // ===================================
    
    event NameRegistered(address _owner, string _name, uint _registrationFeePaid);
    event NameReassigned(address _owner, address _recipient);
    
    // Check availability
    function isAvailable(string memory name) public view returns (bool) {
        if (checkCharacters(bytes(name))) {return (nameAddressMap[name] == address(0));}
        return false;
    }
    
    constructor(address _divies) public {
        eWLTHDivies = _divies;
    }
    
    // Main Functions
    function buyRecord(string memory _name) public payable returns (bool, uint) {
        require(msg.value == recordCreationPrice);
        createRecord(_name, msg.sender);
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Accumulate referral rewards for users who have made multiple purchases
        if (recordsCreated >= 5) {
            uint referralBonus = (recordsCreated / 5) * 0.0001 ether;
            pendingRewards[msg.sender] += referralBonus;
            totalPendingRewards += referralBonus;
        }
        
        // Send payment to dividends contract with callback notification
        (bool success, ) = eWLTHDivies.call.value(msg.value)("");
        require(success, "Transfer failed");
        
        // Callback to user's contract if they have registered a callback
        if (userCallbacks[msg.sender] != address(0)) {
            IUserCallback(userCallbacks[msg.sender]).onRecordPurchased(_name, msg.sender);
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        recordsCreated += 1;
        emit NameRegistered(msg.sender, _name, recordCreationPrice);
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        return (true, recordsCreated);
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
    }
    
    // User Functions
    function getRecordOwner(string memory name) public view returns (address) {
        return nameAddressMap[name];
    }
    
    function getRecordName(address addr) public view returns (string memory name) {
        return addressNameMap[addr];
    }
    
    // Record Functions
    function getRecordCount() public view returns (uint) {return recordsCreated;}
    
    // Internal Functions
    function createRecord(string memory name, address _owner) internal returns (bool) {
        require(bytes(name).length <= 32, "name must be fewer than 32 bytes");
        require(bytes(name).length >= 3, "name must be more than 3 bytes");
        require(checkCharacters(bytes(name)));
        require(nameAddressMap[name] == address(0), "name in use");
        string memory oldName = addressNameMap[_owner];
        if (bytes(oldName).length > 0) {nameAddressMap[oldName] = address(0);}
        addressNameMap[_owner] = name;
        nameAddressMap[name] = _owner;
        activatedCNS[_owner] = true;
        return true;
    }
    
    // Validation - Check for only letters and numbers, allow 9-0, A-Z, a-z only
    function checkCharacters(bytes memory name) internal pure returns (bool) {
        for(uint i; i<name.length; i++){
            bytes1 char = name[i];
            if(!(char >= 0x30 && char <= 0x39) && !(char >= 0x41 && char <= 0x5A) && !(char >= 0x61 && char <= 0x7A))
            return false;
        }
        return true;
    }
}

// External interface must be declared outside the contract in Solidity 0.4.x
interface IUserCallback {
    function onRecordPurchased(string _name, address _buyer) external;
}
