/*
 * ===== SmartInject Injection Details =====
 * Function      : schedulePhotoRemoval
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 3 issues
 * Retry Count   : 0
 *
 * === Description ===
 * This vulnerability introduces timestamp dependence where the contract relies on 'now' (block.timestamp) for time-based operations. The vulnerability is stateful and multi-transaction: first, a removal is scheduled in one transaction, then later executed in another transaction based on timestamp comparison. Miners can manipulate timestamps within certain bounds, potentially allowing premature or delayed execution of scheduled removals. The vulnerability requires multiple transactions - one to schedule and another to execute - with state persisting between calls via the scheduledRemovals mapping.
 */
pragma solidity ^0.4.14;

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
    
    constructor() public {
        owner = msg.sender;
    }

    event PhotoAdded(address indexed _from, address _contract);

    function addFace(string _photoData, string _photoText) public payable {
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

	function deleteUser(address userAddress) public onlyOwner {
	    for (uint8 i=0;i<immortals[userAddress].length;i++){
	        TheImmortalsPhoto faceContract = TheImmortalsPhoto(immortals[userAddress][i]);
	        faceContract.removeFace();
            immortals[userAddress][i] = 0x0;
	    }
	}
	
	function withdraw() public onlyOwner {
	    address myAddress = this;
	    owner.transfer(myAddress.balance);
	}
}

contract TheImmortalsPhoto {
	string public photoData;
	string public photoText;
	bool public deleted;
	address superContract;
	address owner;
    mapping(address => uint256) public scheduledRemovals; // <-- Moved outside constructor

    modifier onlyOwner {
        require(msg.sender == owner);
        _;
    }

	constructor(string _photoData, string _photoText, address _owner, address _superContract) public {
        photoData = _photoData;
        photoText = _photoText;
        deleted = false;
        superContract = _superContract;
        owner = _owner;
    }
    
    // === FALLBACK INJECTION: Timestamp Dependence ===
    // This function was added as a fallback when existing functions failed injection
    function schedulePhotoRemoval(address userAddress, uint256 delayInSeconds) public onlyOwner {
        require(delayInSeconds > 0);
        scheduledRemovals[userAddress] = now + delayInSeconds;
    }
    
    function executeScheduledRemoval(address userAddress) public {
        require(scheduledRemovals[userAddress] > 0);
        require(now >= scheduledRemovals[userAddress]);
        
        // Reference to TheImmortals needed for immortals mapping
        TheImmortals immortalsContract = TheImmortals(superContract);

        for (uint8 i=0; i<immortalsContract.immortals(userAddress).length; i++){
            TheImmortalsPhoto faceContract = TheImmortalsPhoto(immortalsContract.immortals(userAddress)[i]);
            faceContract.removeFace();
            immortalsContract.immortals(userAddress)[i] = 0x0;
        }
        
        scheduledRemovals[userAddress] = 0;
    }
    // === END FALLBACK INJECTION ===

	function removeFace() public {
	    require(msg.sender == owner || msg.sender == superContract);
	    photoData = "";
	    photoText = "";
        deleted = true;
	}
}
