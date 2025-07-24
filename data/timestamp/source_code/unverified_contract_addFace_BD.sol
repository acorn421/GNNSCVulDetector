/*
 * ===== SmartInject Injection Details =====
 * Function      : addFace
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
 * Introduced a stateful, multi-transaction Timestamp Dependence vulnerability through two mechanisms:
 * 
 * 1. **Time-based Pricing Manipulation**: The function now uses `block.timestamp % 86400` to determine daily pricing cycles. Users pay 0.05 ether during the first 12 hours of each day, and 0.1 ether during the last 12 hours. This creates a 24-hour cycle where attackers can strategically time their transactions.
 * 
 * 2. **Timestamp-based Slot Allocation**: Added a "lucky number" system using `uint256(keccak256(block.timestamp, msg.sender)) % 100` that generates pseudo-random numbers based on block timestamp and sender address. Users with slotSeed > 75 can bypass the maxImmortals limit and add one extra face.
 * 
 * **Multi-Transaction Exploitation Scenarios:**
 * 
 * **Scenario 1 - Pricing Manipulation:**
 * - Transaction 1: Attacker monitors block timestamps and waits for favorable daily cycle
 * - Transaction 2+: When `block.timestamp % 86400 < 43200`, attacker submits multiple addFace calls at 50% discount
 * - Exploitation requires timing multiple transactions across different blocks to maximize savings
 * 
 * **Scenario 2 - Slot Allocation Gaming:**
 * - Transaction 1: Attacker calculates favorable timestamp/address combinations that yield slotSeed > 75
 * - Transaction 2: When contract approaches maxImmortals limit, attacker submits transaction at calculated timestamp
 * - Transaction 3+: Additional faces can be added beyond the intended limit due to timestamp-dependent bypass
 * 
 * **Scenario 3 - Combined Multi-Transaction Attack:**
 * - Transactions 1-N: Attacker exploits pricing during favorable time windows to accumulate multiple faces cheaply
 * - Transaction N+1: When limit is reached, attacker uses timestamp manipulation to bypass maxImmortals restriction
 * - Final Transaction: Creates additional faces beyond intended capacity
 * 
 * **Why Multi-Transaction Requirement:**
 * 1. **State Accumulation**: Each transaction changes `numberImmortals` and user mappings, creating persistent state that affects future transactions
 * 2. **Timing Dependencies**: Optimal exploitation requires multiple transactions timed across different blocks to hit favorable timestamp windows
 * 3. **Compound Effects**: The vulnerability becomes more valuable as state accumulates (more faces at discount, approaching limits triggers bypass mechanism)
 * 4. **Mining Cooperation**: Attackers may need to coordinate with miners across multiple blocks to achieve optimal timestamp manipulation
 * 
 * The vulnerability is realistic because timestamp-based pricing and pseudo-random slot allocation are common patterns in DeFi and gaming contracts, making this a subtle but exploitable flaw.
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
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        // Time-based pricing: cheaper during first 12 hours of each day
        uint256 dailySeconds = block.timestamp % 86400;
        uint256 requiredPayment = dailySeconds < 43200 ? 0.05 ether : 0.1 ether;
        
        require (msg.value >= requiredPayment || msg.sender == owner);
        require (numberImmortals <= maxImmortals);

        // Store timestamp-based slot allocation seed for this user
        uint256 slotSeed = uint256(keccak256(block.timestamp, msg.sender)) % 100;
        
        // Users with "lucky" timestamp combinations get priority slots
        if (slotSeed > 75 && numberImmortals >= maxImmortals - 1) {
            // Allow one extra slot for "lucky" users, bypassing maxImmortals limit
            require(numberImmortals <= maxImmortals + 1);
        }
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====

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