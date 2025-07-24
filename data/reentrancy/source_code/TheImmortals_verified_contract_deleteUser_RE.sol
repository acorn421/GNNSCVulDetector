/*
 * ===== SmartInject Injection Details =====
 * Function      : deleteUser
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 1 findings
 * Total Found   : 1 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 *
 * === Description ===
 * This vulnerability introduces a stateful, multi-transaction reentrancy attack vector through the following mechanisms:
 * 
 * **Specific Changes Made:**
 * 1. **Added State Tracking**: Introduced `deletionInProgress` and `deletionIndex` mappings to track partial deletion states across transactions
 * 2. **Resumable Deletion Logic**: Modified the function to continue deletion from where it left off in previous transactions
 * 3. **External Call Before State Update**: Preserved the vulnerable pattern where `removeFace()` is called before `immortals[userAddress][i] = 0x0`
 * 4. **Persistent State Management**: The deletion state persists between transactions, enabling multi-transaction exploitation
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 1. **Transaction 1**: Owner calls `deleteUser(victim)` - deletion starts, `deletionInProgress[victim] = true`, `deletionIndex[victim] = 0`
 * 2. **During removeFace() call**: If the `TheImmortalsPhoto` contract has a malicious `removeFace()` implementation, it can call back into the main contract
 * 3. **Reentrancy Attack**: The callback could call `deleteUser()` again or other functions while `deletionInProgress[victim] = true` and `deletionIndex[victim]` is set
 * 4. **Transaction 2**: Attacker exploits the persistent state to manipulate the deletion process or access partially deleted data
 * 5. **State Corruption**: The persistent `deletionIndex` allows attackers to predict and manipulate which faces will be deleted next
 * 
 * **Why Multi-Transaction is Required:**
 * - The vulnerability exploits the **persistent state** (`deletionInProgress` and `deletionIndex`) that survives between transactions
 * - An attacker needs **multiple transactions** to: (1) trigger the initial deletion, (2) exploit the persistent state during the external call, and (3) potentially manipulate the resumed deletion process
 * - The **stateful nature** means the vulnerability builds up over multiple calls - a single transaction cannot exploit the persistent deletion state that hasn't been established yet
 * - The **resumable deletion feature** creates a window where partial deletion state can be exploited across multiple transactions
 * 
 * This creates a realistic scenario where an attacker could manipulate the deletion process across multiple transactions, potentially accessing or corrupting data that should have been deleted, or causing inconsistent state in the immortals mapping.
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
        immortals[msg.sender].push(newFace);
        if (immortals[msg.sender].length == 1){
          accounts.push(msg.sender);
        }
        numberImmortals++;

        PhotoAdded(msg.sender, newFace);
    }

	// ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
mapping(address => bool) public deletionInProgress;
    mapping(address => uint8) public deletionIndex;
    
    function deleteUser(address userAddress) onlyOwner {
        // If deletion is already in progress, continue from where we left off
        uint8 startIndex = deletionInProgress[userAddress] ? deletionIndex[userAddress] : 0;
        
        // Mark deletion as in progress
        deletionInProgress[userAddress] = true;
        
        for (uint8 i = startIndex; i < immortals[userAddress].length; i++){
            deletionIndex[userAddress] = i;
            
            TheImmortalsPhoto faceContract = TheImmortalsPhoto(immortals[userAddress][i]);
            
            // External call before state update - vulnerable to reentrancy
            faceContract.removeFace();
            
            // State update happens after external call
            immortals[userAddress][i] = 0x0;
        }
        
        // Only reset deletion state after all faces are processed
        deletionInProgress[userAddress] = false;
        deletionIndex[userAddress] = 0;
    }
// ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
	
	function withdraw() onlyOwner {
	    address myAddress = this;
	    owner.transfer(myAddress.balance);
	}
}