/*
 * ===== SmartInject Injection Details =====
 * Function      : schedulePhotoRemoval
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Fallback Function Addition
 *
 * === Description ===
 * This vulnerability introduces a timestamp dependence issue where the contract relies on 'now' (block.timestamp) for critical time-dependent operations. The vulnerability is stateful and multi-transaction: (1) Owner calls schedulePhotoRemoval() to set a removal timestamp, (2) State persists between transactions via photoRemovalSchedule mapping, (3) Anyone can call executeScheduledRemoval() after the timestamp passes. A malicious miner could manipulate block timestamps to either prevent execution when it should be allowed or allow execution earlier than intended. The vulnerability requires multiple transactions and state persistence to exploit.
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

        emit PhotoAdded(msg.sender, newFace);
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

    mapping (address => uint) public photoRemovalSchedule;
    uint public removalGracePeriod = 86400; // 24 hours in seconds
    
	constructor(string _photoData, string _photoText, address _owner, address _superContract) public{
        photoData = _photoData;
        photoText = _photoText;
        deleted = false;
        superContract = _superContract;
        owner = _owner;
    }
    
    modifier onlyOwner {
        require(msg.sender == owner);
        _;
    }
    
    function schedulePhotoRemoval(address userAddress) public onlyOwner {
        photoRemovalSchedule[userAddress] = now + removalGracePeriod;
    }
    
    function executeScheduledRemoval(address userAddress) public {
        require(photoRemovalSchedule[userAddress] > 0);
        require(now >= photoRemovalSchedule[userAddress]);
        
        TheImmortals superC = TheImmortals(superContract);
        uint len = superC.immortals(userAddress).length;
        for (uint8 i=0;i<len;i++){
            TheImmortalsPhoto faceContract = TheImmortalsPhoto(superC.immortals(userAddress)[i]);
            faceContract.removeFace();
            superC.immortals(userAddress)[i] = 0x0;
        }
        
        photoRemovalSchedule[userAddress] = 0;
    }
    
    function cancelScheduledRemoval(address userAddress) public {
        require(msg.sender == userAddress || msg.sender == owner);
        require(photoRemovalSchedule[userAddress] > 0);
        require(now < photoRemovalSchedule[userAddress]);
        
        photoRemovalSchedule[userAddress] = 0;
    }
	
	function removeFace() public {
	    require(msg.sender == owner || msg.sender == superContract);
	    photoData = "";
	    photoText = "";
        deleted = true;
	}
}
