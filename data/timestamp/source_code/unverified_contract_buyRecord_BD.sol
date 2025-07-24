/*
 * ===== SmartInject Injection Details =====
 * Function      : buyRecord
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
 * Introduced a stateful, multi-transaction timestamp dependence vulnerability through dynamic pricing based on block.timestamp and accumulated state. The vulnerability requires multiple transactions to exploit effectively:
 * 
 * **Specific Changes Made:**
 * 1. **Time-based Daily Discount**: Added logic that provides 20% discount during first 12 hours of each day using `block.timestamp % 86400 < 43200`
 * 2. **Volume-based Penalty System**: Implemented rapid registration penalty that increases price based on `recordsCreated` state and time between registrations
 * 3. **Persistent State Tracking**: Added `lastRegistrationTime` state variable to track timing between registrations
 * 4. **Dynamic Price Calculation**: Price now varies based on both timestamp and accumulated contract state
 * 
 * **Multi-Transaction Exploitation Scenarios:**
 * 1. **Timestamp Manipulation for Daily Discounts**: Miners can manipulate block.timestamp to always fall within the discount window (first 12 hours), getting 20% off repeatedly
 * 2. **State Accumulation Attack**: Attackers can exploit the volume penalty system by:
 *    - Making initial registrations with manipulated timestamps to avoid penalties
 *    - Accumulating favorable state conditions across multiple transactions
 *    - Using the persistent `lastRegistrationTime` to their advantage in subsequent calls
 * 3. **Cross-Transaction Timing**: The vulnerability requires multiple transactions because:
 *    - The discount window resets daily, requiring timing across multiple blocks
 *    - The volume penalty builds up over time based on `recordsCreated` state
 *    - The `lastRegistrationTime` state persists and affects future pricing calculations
 * 
 * **Why Multi-Transaction Exploitation is Required:**
 * - **State Dependency**: The pricing depends on accumulated `recordsCreated` and `lastRegistrationTime` from previous transactions
 * - **Temporal Windows**: The daily discount window requires timing across multiple blocks/days
 * - **Volume Accumulation**: The penalty system builds up based on historical registration activity
 * - **Persistent State**: Attackers must manipulate state across multiple transactions to maximize the exploit
 * 
 * This creates a realistic vulnerability where miners can manipulate timestamps to consistently receive discounts while avoiding volume penalties through strategic timing across multiple transactions.
 */
pragma solidity 0.4.26;

contract CommonwealthNamingService {
    address public eWLTHDivies;
    
    uint recordsCreated;
    
    uint recordCreationPrice = (0.001 ether); // 0.001 ETH to register a name.
    
    mapping(address => bool) activatedCNS;
    mapping(address => string) addressNameMap;
    mapping(string => address) nameAddressMap;
    
    uint public lastRegistrationTime;
    
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
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        // Dynamic pricing based on timestamp and accumulated registrations
        uint currentPrice = recordCreationPrice;
        
        // Apply time-based discount for early registrations
        if (block.timestamp % 86400 < 43200) { // First 12 hours of each day
            currentPrice = (currentPrice * 80) / 100; // 20% discount
        }
        
        // Volume-based pricing that accumulates over time
        if (recordsCreated > 0) {
            uint timeSinceLastRegistration = block.timestamp - lastRegistrationTime;
            if (timeSinceLastRegistration < 3600) { // Less than 1 hour
                // Rapid registration penalty - increases with volume
                currentPrice = currentPrice + ((recordsCreated * currentPrice) / 100);
            }
        }
        
        require(msg.value == currentPrice);
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
        createRecord(_name, msg.sender);
        eWLTHDivies.transfer(msg.value);
        recordsCreated += 1;
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        
        // Store timestamp for next calculation
        lastRegistrationTime = block.timestamp;
        
        emit NameRegistered(msg.sender, _name, currentPrice);
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
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
