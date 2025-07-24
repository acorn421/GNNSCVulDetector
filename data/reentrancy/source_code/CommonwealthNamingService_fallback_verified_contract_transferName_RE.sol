/*
 * ===== SmartInject Injection Details =====
 * Function      : transferName
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 3 findings
 * Total Found   : 3 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-benign (SWC-107)
 * 3. reentrancy-events (SWC-107)
 *
 * === Description ===
 * This function introduces a multi-transaction reentrancy vulnerability. The vulnerability requires: 1) An attacker to first own a name (transaction 1), 2) Create a malicious contract that implements onNameReceived (transaction 2), 3) Call transferName which makes an external call before updating state (transaction 3), 4) The malicious contract can reenter and call transferName again before the first call completes, allowing double-transfers or manipulation of the name ownership state across multiple transactions.
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

    // === FALLBACK INJECTION: Reentrancy ===
    // This function was added as a fallback when existing functions failed injection
    // Transfer name to another address with external call
    function transferName(address _recipient, string memory _name) public {
        require(nameAddressMap[_name] == msg.sender, "only owner can transfer");
        require(_recipient != address(0), "invalid recipient");
        require(bytes(_name).length > 0, "invalid name");
        
        // Clear old mapping first
        nameAddressMap[_name] = address(0);
        addressNameMap[msg.sender] = "";
        
        // External call to recipient - vulnerable to reentrancy
        if (_recipient.call(bytes4(keccak256("onNameReceived(string)")), _name)) {
            // Continue with transfer after external call
            nameAddressMap[_name] = _recipient;
            addressNameMap[_recipient] = _name;
            activatedCNS[_recipient] = true;
            emit NameReassigned(msg.sender, _recipient);
        } else {
            // Revert changes if call fails
            nameAddressMap[_name] = msg.sender;
            addressNameMap[msg.sender] = _name;
        }
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
        return (true, recordsCreated);
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
