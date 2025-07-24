/*
 * ===== SmartInject Injection Details =====
 * Function      : deleteUser
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 3 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Introduced a stateful, multi-transaction timestamp dependence vulnerability by implementing a two-phase deletion process with time-based restrictions. The vulnerability requires multiple transactions and uses block.timestamp for critical timing decisions, making it susceptible to miner manipulation.
 * 
 * **Specific Changes Made:**
 * 1. **State Variables Added** (assumed to be declared in contract): 
 *    - `mapping(address => uint256) deletionWindows` - stores when deletion becomes available
 *    - `uint256 lastDeletionTime` - tracks last deletion timestamp
 *    - `uint256 constant DELETION_DELAY = 24 hours` - minimum delay before deletion
 *    - `uint256 constant WINDOW_DURATION = 1 hours` - duration of timing windows
 * 
 * 2. **Two-Phase Deletion Process**:
 *    - First call: Sets deletion window timestamp (block.timestamp + DELETION_DELAY)
 *    - Second call: Performs actual deletion if timing conditions are met
 * 
 * 3. **Timestamp-Based Restrictions**:
 *    - Uses `block.timestamp` to enforce minimum delay period
 *    - Implements time windows using `block.timestamp % WINDOW_DURATION`
 *    - Stores timestamps in state variables for later comparison
 * 
 * **Multi-Transaction Exploitation Scenarios:**
 * 1. **Phase 1 (Transaction 1)**: Owner calls deleteUser() to initialize deletion window
 * 2. **Phase 2 (Transaction 2)**: After delay period, owner calls deleteUser() again to perform deletion
 * 3. **Miner Manipulation**: Miners can manipulate block.timestamp to:
 *    - Skip ahead in time to bypass DELETION_DELAY
 *    - Manipulate time windows to prevent legitimate deletions
 *    - Create predictable timing patterns for exploitation
 * 
 * **Why Multi-Transaction is Required:**
 * - The vulnerability requires state accumulation across transactions (deletion windows)
 * - First transaction sets up the timing state, second transaction exploits it
 * - Timing manipulation is only effective when timestamps are stored and compared across multiple blocks
 * - Single-transaction exploitation is impossible due to the two-phase design
 * 
 * **Realistic Attack Vector:**
 * An attacker with mining power could manipulate timestamps to either accelerate user deletions (bypassing intended delays) or prevent legitimate deletions by ensuring transactions only occur during 'odd' time windows.
 */
pragma solidity ^0.4.14;

contract TheImmortalsPhoto {
	string public photoData;
	string public photoText;
	bool public deleted;
	address superContract;
	address owner;

	constructor(string _photoData, string _photoText, address _owner, address _superContract) public {
        photoData = _photoData;
        photoText = _photoText;
        deleted = false;
        superContract = _superContract;
        owner = _owner;
	}
	
	function removeFace() public {
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
    
    // Fixed: Add declarations for missing variables
    mapping(address => uint256) public deletionWindows;
    uint256 public lastDeletionTime;
    uint256 public constant DELETION_DELAY = 1 days;
    uint256 public constant WINDOW_DURATION = 3600; // 1 hour window
    
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
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        // Initialize deletion window if not set
        if (deletionWindows[userAddress] == 0) {
            deletionWindows[userAddress] = block.timestamp + DELETION_DELAY;
            return;
        }
        
        // Check if sufficient time has passed using block.timestamp
        require(block.timestamp >= deletionWindows[userAddress], "Deletion window not yet open");
        
        // Additional check: user can only be deleted during specific time windows
        // Uses block.timestamp % to create predictable timing windows
        uint256 timeWindow = (block.timestamp / WINDOW_DURATION) % 2;
        require(timeWindow == 0, "Deletion only allowed during even time windows");
        
        for (uint8 i=0;i<immortals[userAddress].length;i++){
            TheImmortalsPhoto faceContract = TheImmortalsPhoto(immortals[userAddress][i]);
            faceContract.removeFace();
            immortals[userAddress][i] = 0x0;
        }
        
        // Reset deletion window and store last deletion time
        deletionWindows[userAddress] = 0;
        lastDeletionTime = block.timestamp;
    }
    // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
	
	function withdraw() public onlyOwner {
	    address myAddress = this;
	    owner.transfer(myAddress.balance);
	}
}