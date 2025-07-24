/*
 * ===== SmartInject Injection Details =====
 * Function      : renewRecord
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
 * This vulnerability introduces a multi-transaction timestamp dependence attack in the naming service renewal system. The attack requires: 1) Initial record creation and renewal to establish expiry timestamps, 2) Miner manipulation of block timestamps during the renewal window, 3) Claiming expired records based on manipulated timestamps. The vulnerability persists across multiple transactions and allows malicious miners to steal domain names by manipulating timestamps within the ~15 second tolerance window.
 */
pragma solidity 0.4.26;

contract CommonwealthNamingService {
    address public eWLTHDivies;
    
    uint recordsCreated;
    
    uint recordCreationPrice = (0.001 ether); // 0.001 ETH to register a name.
    
    mapping(address => bool) activatedCNS;
    mapping(address => string) addressNameMap;
    mapping(string => address) nameAddressMap;
    
    event NameRegistered(address _owner, string _name, uint _registrationFeePaid);
    event NameReassigned(address _owner, address _recipient);
    
    // Check availability
    function isAvailable(string memory name) public view returns (bool) {
        if (checkCharacters(bytes(name))) {return (nameAddressMap[name] == address(0));}
        return false;
    }
    
    // === FALLBACK INJECTION: Timestamp Dependence ===
    // This function was added as a fallback when existing functions failed injection
    // New state variables needed for renewal system
    mapping(string => uint) recordExpiryTime;
    mapping(string => uint) recordRenewalCount;
    uint public renewalPeriod = 365 days;
    uint public renewalPrice = 0.0005 ether;
    
    // Function to renew a record based on timestamp
    function renewRecord(string memory name) public payable returns (bool) {
        require(msg.value == renewalPrice, "Incorrect renewal fee");
        require(nameAddressMap[name] == msg.sender, "Only owner can renew");
        
        // Vulnerable: Using block.timestamp for critical business logic
        // This allows miners to manipulate timestamps within ~15 seconds
        uint currentTime = block.timestamp;
        uint expiryTime = recordExpiryTime[name];
        
        // Multi-transaction vulnerability: 
        // 1. First transaction sets initial expiry
        // 2. Subsequent transactions can be manipulated by miners
        if (expiryTime == 0) {
            // First renewal - set initial expiry
            recordExpiryTime[name] = currentTime + renewalPeriod;
        } else {
            // Subsequent renewals - vulnerable to timestamp manipulation
            require(currentTime >= expiryTime - 30 days, "Too early to renew");
            recordExpiryTime[name] = currentTime + renewalPeriod;
        }
        
        recordRenewalCount[name] += 1;
        eWLTHDivies.transfer(msg.value);
        return true;
    }
    
    // Function to check if record is expired (also vulnerable)
    function isRecordExpired(string memory name) public view returns (bool) {
        uint expiryTime = recordExpiryTime[name];
        if (expiryTime == 0) return false; // Never been renewed
        return block.timestamp > expiryTime;
    }
    
    // Function to claim expired records (completes the multi-transaction attack)
    function claimExpiredRecord(string memory name) public payable returns (bool) {
        require(msg.value == recordCreationPrice, "Incorrect creation fee");
        require(isRecordExpired(name), "Record not expired");
        
        // Remove old owner mapping
        address oldOwner = nameAddressMap[name];
        if (oldOwner != address(0)) {
            addressNameMap[oldOwner] = "";
            activatedCNS[oldOwner] = false;
        }
        
        // Assign to new owner
        addressNameMap[msg.sender] = name;
        nameAddressMap[name] = msg.sender;
        activatedCNS[msg.sender] = true;
        
        // Reset renewal data
        recordExpiryTime[name] = 0;
        recordRenewalCount[name] = 0;
        
        eWLTHDivies.transfer(msg.value);
        emit NameRegistered(msg.sender, name, recordCreationPrice);
        return true;
    }
    // === END FALLBACK INJECTION ===

    constructor(address _divies) public {
        eWLTHDivies = _divies;
    }
    
    // Main Functions
    function buyRecord(string memory _name) public payable returns (bool, uint) {
        require(msg.value == recordCreationPrice);
        createRecord(_name, msg.sender);
        eWLTHDivies.transfer(msg.value);
        recordsCreated += 1;
        emit NameRegistered(msg.sender, _name, recordCreationPrice);
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
