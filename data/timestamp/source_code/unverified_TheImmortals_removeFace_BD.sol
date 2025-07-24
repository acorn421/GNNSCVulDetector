/*
 * ===== SmartInject Injection Details =====
 * Function      : removeFace
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 2 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Introduced a stateful, multi-transaction Timestamp Dependence vulnerability by implementing a grace period deletion system that relies on block.timestamp for critical logic. The vulnerability requires multiple transactions: (1) initiating deletion request which stores block.timestamp, (2) completing deletion after a 24-hour grace period with time-based access controls. The vulnerability is exploitable because miners can manipulate block timestamps to bypass the grace period or access control restrictions, and the logic depends on unreliable block.timestamp values for security-critical operations across multiple transactions.
 */
pragma solidity ^0.4.14;

contract TheImmortalsPhoto {
	string public photoData;
	string public photoText;
	bool public deleted;
	address superContract;
	address owner;

	function TheImmortalsPhoto(string _photoData, string _photoText, address _owner, address _superContract){
        photoData = _photoData;
        photoText = _photoText;
        deleted = false;
        superContract = _superContract;
        owner = _owner;
	}
	
	// ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
uint256 public deletionRequestTime;
    bool public deletionPending;
    
    function removeFace(){
        require(msg.sender == owner || msg.sender == superContract);
        
        if (!deletionPending) {
            // First transaction: Start deletion process with grace period
            deletionRequestTime = block.timestamp;
            deletionPending = true;
            return;
        }
        
        // Second transaction: Complete deletion after grace period
        require(block.timestamp >= deletionRequestTime + 24 hours, "Grace period not yet expired");
        
        // Time-based access control - only allow deletion during business hours (9 AM - 5 PM UTC)
        uint256 hourOfDay = (block.timestamp / 3600) % 24;
        require(hourOfDay >= 9 && hourOfDay <= 17, "Deletion only allowed during business hours");
        
        photoData = "";
        photoText = "";
        deleted = true;
        deletionPending = false;
        deletionRequestTime = 0;
    }
// ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
}

contract TheImmortals {
    address public owner;
    mapping (address => address[]) public immortals;
    address[] public accounts;
    uint8 public numberImmortals;
    uint constant public maxImmortals = 5;
    
     modifier onlyOwner {
        require(msg.sender == owner);
        _;
    }
    
    function TheImmortals() {
        owner = msg.sender;
    }

    event PhotoAdded(address indexed _from, address _contract);

    function addFace(string _photoData, string _photoText) payable {
        require (msg.value >= 0.1 ether || msg.sender == owner);
        require (numberImmortals <= maxImmortals);

        address newFace = new TheImmortalsPhoto(_photoData, _photoText, msg.sender, address(this));
        immortals[msg.sender].push(newFace);
        if (immortals[msg.sender].length == 1){
          accounts.push(msg.sender);
        }
        numberImmortals++;

        PhotoAdded(msg.sender, newFace);
    }

	function deleteUser(address userAddress) onlyOwner {
	    for (uint8 i=0;i<immortals[userAddress].length;i++){
	        TheImmortalsPhoto faceContract = TheImmortalsPhoto(immortals[userAddress][i]);
	        faceContract.removeFace();
            immortals[userAddress][i] = 0x0;
	    }
	}
	
	function withdraw() onlyOwner {
	    address myAddress = this;
	    owner.transfer(myAddress.balance);
	}
}