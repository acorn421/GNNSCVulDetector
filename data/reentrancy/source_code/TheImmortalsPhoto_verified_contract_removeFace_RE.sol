/*
 * ===== SmartInject Injection Details =====
 * Function      : removeFace
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 2 findings
 * Total Found   : 2 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-benign (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the owner's contract before setting the deleted flag. This creates a vulnerability that requires multiple transactions to exploit effectively:
 * 
 * **Specific Changes Made:**
 * 1. Added an external call to the owner's contract using `owner.call()` to notify about photo removal
 * 2. The external call is made AFTER clearing photoData and photoText but BEFORE setting deleted=true
 * 3. This violates the Checks-Effects-Interactions pattern and creates a reentrancy window
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 1. **Transaction 1**: Attacker (who is the owner) calls removeFace() which triggers the external call to owner.call()
 * 2. **During the external call**: The attacker's malicious contract receives the callback and can re-enter removeFace() while deleted is still false
 * 3. **State Persistence**: The photoData and photoText are already cleared from the first call, but deleted remains false
 * 4. **Transaction 2**: The attacker can exploit this inconsistent state where the photo data appears removed but the contract still thinks it's active
 * 5. **Later Transactions**: The attacker can manipulate this inconsistent state across multiple transactions
 * 
 * **Why Multiple Transactions Are Required:**
 * - The vulnerability requires the attacker to first trigger the external call (Transaction 1)
 * - The reentrancy callback allows state manipulation during the external call
 * - The persistent state changes (photoData cleared, deleted still false) enable exploitation in subsequent transactions
 * - The attacker can use this state inconsistency to bypass checks in other functions that rely on the deleted flag
 * - The vulnerability becomes more powerful when combined with other contract functions that check the deleted state
 * 
 * **State Persistence Element:**
 * - The cleared photoData and photoText persist between transactions
 * - The deleted flag remains false during the reentrancy window
 * - This creates a multi-transaction exploitable state where the contract appears partially removed but still active
 * - Subsequent transactions can exploit this inconsistent state for various attacks
 * 
 * This vulnerability is realistic because notification callbacks are common in production contracts, and the state inconsistency creates genuine security risks that accumulate across multiple transactions.
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
    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
    require(msg.sender == owner || msg.sender == superContract);
    photoData = "";
    photoText = "";
    
    // Notify external registry or analytics contract about the removal
    if (owner != address(0)) {
        // External call before setting deleted flag - creates reentrancy window
        bool success = owner.call(bytes4(keccak256("onPhotoRemoved(address,address)")), address(this), msg.sender);
    }
    
    deleted = true;
}
    // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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