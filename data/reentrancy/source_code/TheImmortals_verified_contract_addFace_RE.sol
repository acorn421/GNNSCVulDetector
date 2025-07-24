/*
 * ===== SmartInject Injection Details =====
 * Function      : addFace
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 4 findings
 * Total Found   : 5 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-no-eth (SWC-107)
 * 3. reentrancy-benign (SWC-107)
 * ... and 1 more
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to a user-controlled contract (existing photo) before state updates. The vulnerability requires multiple transactions to exploit: 1) First transaction creates initial photo, 2) Second transaction triggers the external call which can re-enter addFace before numberImmortals is incremented, potentially bypassing the maxImmortals limit. The vulnerability is stateful because it depends on the user having existing photos from previous transactions, and the external call is made to a contract address that was stored in previous transactions. This creates a realistic scenario where users with existing photos can exploit the validation mechanism during subsequent photo additions.
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
	
	function removeFace(){
	    require(msg.sender == owner || msg.sender == superContract);
	    photoData = "";
	    photoText = "";
        deleted = true;
	}
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
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Notify external validation service about new photo creation
        if (immortals[msg.sender].length > 0) {
            // For users with existing photos, call their first photo contract for validation
            TheImmortalsPhoto existingPhoto = TheImmortalsPhoto(immortals[msg.sender][0]);
            // External call to user-controlled contract before state updates
            existingPhoto.call(bytes4(keccak256("validateNewPhoto(address,string)")), newFace, _photoData);
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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