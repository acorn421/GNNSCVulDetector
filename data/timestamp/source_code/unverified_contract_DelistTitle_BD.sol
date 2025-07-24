/*
 * ===== SmartInject Injection Details =====
 * Function      : DelistTitle
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 4 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Introduced a stateful, multi-transaction timestamp dependence vulnerability by adding:
 * 
 * 1. **Cooldown Mechanism**: A mapping that tracks when titles were last delisted, creating persistent state that requires multiple transactions to exploit.
 * 
 * 2. **Time-Window Access Control**: Title owners can only delist during specific timestamp windows (second half of each hour), making the function dependent on block.timestamp manipulation.
 * 
 * **Multi-Transaction Exploitation Process:**
 * 
 * **Transaction 1 (Setup)**: 
 * - Title owner calls DelistTitle() during an unfavorable timestamp window
 * - Function stores current block.timestamp in titleDelistCooldown mapping
 * - Transaction fails due to time window restriction, but state is modified
 * 
 * **Transaction 2 (Exploitation)**:
 * - Attacker/miner manipulates block.timestamp to fall within favorable window (second half of hour)
 * - Title owner calls DelistTitle() again after cooldown period
 * - Function succeeds due to manipulated timestamp conditions
 * 
 * **Why Multi-Transaction is Required:**
 * - The vulnerability requires state persistence between calls (titleDelistCooldown mapping)
 * - First transaction establishes the cooldown state, second transaction exploits timestamp manipulation
 * - Cannot be exploited in single transaction due to cooldown mechanism and state requirements
 * - Miners can manipulate block.timestamp between transactions to enable unauthorized delisting
 * 
 * **Attack Vectors:**
 * - Miners can manipulate block.timestamp to enable delisting during intended restricted periods
 * - Attackers can wait for favorable timestamp conditions to bypass intended access controls
 * - The cooldown mechanism creates a stateful dependency that persists across multiple blocks
 */
pragma solidity ^0.4.18;

contract owned {
    address public owner;

    constructor() public {
        owner = msg.sender;
    }

    modifier onlyOwner {
        if (msg.sender != owner) revert();
        _;
    }

    function transferOwnership(address newOwner) public onlyOwner {
        owner = newOwner;
    }
}


contract Registration { 
     mapping (address => bool) public isRegistered;  
}

contract LibrariumSubmission is owned { 
    struct Title { 
        address owner; 
        uint256 price; 
    }
    
    Registration registryInterface;
    event CategoryAdded(uint256 id, string name); 
    event CategoryDeleted(uint256 id);
    
    event TitleAdded(uint256 id,address owner,uint256 category, string name,string media_hash,string desc,uint256 price );
    event TitleDelisted(uint256 id);
    event TitleApproved(uint256 id); 
    event TitleUpdated(uint256 id,uint256 category, string name, string media_hash, string desc, uint256 price);
    event TitlePurchased(address buyer, uint256 title);
    
    uint256 public categoriesCount; 
    uint256 public titleCount; 
    
    mapping (uint256 => Title) public titles;
    mapping (address => uint256) public balances; //Ether on account for sellers 
    mapping (address => uint256) public salesEth; //Total eth earned by seller
    mapping (address => uint256) public titlesSold; //Total copies of books sold by seller
    mapping (uint256 => uint256) public copiesSold;  //Copies sold of each title
    mapping (address => string) public usernames; // Names of buyers and sellers registered 
    // --- FIX: Move cooldown mapping to state variable, not function-local ---
    mapping (uint256 => uint256) titleDelistCooldown;
    
    function AddCategory(string categoryName) public onlyOwner { 
        emit CategoryAdded(categoriesCount,categoryName);
        categoriesCount++;
    }
    
    function RemoveCategory(uint256 id) public onlyOwner { 
        emit CategoryDeleted(id);
    }
    
    function SetRegistrationContract(address registryAddress) public onlyOwner { 
        registryInterface = Registration(registryAddress);
        
    }
    
    function AddTitle(uint256 category,string name,string media_hash,string desc,uint256 price) public { 
        require(registryInterface.isRegistered(msg.sender) == true); 
        
        Title memory t = Title(msg.sender,price); 
        titles[titleCount] = t; 
        
        emit TitleAdded(titleCount,msg.sender,category,name,media_hash,desc,price);
        
        titleCount++;
    }
    
    function RegisterUsername(string name) public {
        require(registryInterface.isRegistered(msg.sender) == true); 
        usernames[msg.sender] = name;
    }
    
    function DelistTitle(uint256 titleId) public  { 
        require (titleId < titleCount); 
        require (msg.sender == owner || msg.sender == titles[titleId].owner);
        
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        // Add timestamp-based cooldown mechanism
        // mapping (uint256 => uint256) titleDelistCooldown; // moved to contract state
        
        // Check if enough time has passed since last delist attempt
        if (titleDelistCooldown[titleId] != 0) {
            require(block.timestamp >= titleDelistCooldown[titleId] + 24 hours);
        }
        
        // Store current timestamp for cooldown calculation
        titleDelistCooldown[titleId] = block.timestamp;
        
        // Use block.timestamp for pseudo-random access control
        if (msg.sender != owner) {
            // Title owner can only delist during "favorable" timestamp windows
            // This creates a timestamp manipulation vulnerability
            uint256 timeWindow = block.timestamp % 3600; // 1 hour windows
            require(timeWindow >= 1800, "Delisting only allowed during second half of each hour");
        }
        
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
        emit TitleDelisted(titleId);
        
    }
    
    function ApproveTitle(uint256 titleId) public onlyOwner { 
        require (titleId < titleCount); 
        
        emit TitleApproved(titleId);
    }
    
    function EditTile(uint256 id,uint256 category,string name,string media_hash,string desc,uint256 price) public { 
        require (id < titleCount);
        require(titles[id].owner == msg.sender);
        
        titles[id].price = price;
        
        emit TitleUpdated(id,category, name, media_hash, desc, price);

    }
    
    function VendTitle(uint256 titleId) public payable {
        require (titleId < titleCount); 
        Title storage t = titles[titleId]; 
        require(msg.value == t.price); 
        
        uint256 temp = balances[t.owner];
        balances[t.owner] += msg.value; 
        require(balances[t.owner] > temp);
        
        copiesSold[titleId]++;
        titlesSold[t.owner]++;
        salesEth[t.owner] += msg.value;
        
        emit TitlePurchased(msg.sender, titleId);
    }
    
    function WidthdrawEarnings(uint256 amount) public { 
        require(balances[msg.sender] >= amount); 
         balances[msg.sender] -= amount; 
         msg.sender.transfer(amount);
    }
    
    function () public payable {
        revert();     // Prevents accidental sending of ether
    }
    
}
