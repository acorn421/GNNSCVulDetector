/*
 * ===== SmartInject Injection Details =====
 * Function      : AddTitle
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 7 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Introduced a timestamp dependence vulnerability that creates a multi-transaction exploit scenario. The vulnerability stems from using block.timestamp for time-based pricing logic that compares submission times across multiple transactions. 
 * 
 * **Key Changes Made:**
 * 1. **Timestamp Storage**: Added `submissionTime` variable that stores `block.timestamp` for each title submission
 * 2. **Multi-Transaction State Dependency**: The pricing logic now depends on the timestamp stored in the previous title (from previous transactions)
 * 3. **Time-based Pricing Logic**: Implemented dynamic pricing based on time differences between consecutive submissions
 * 4. **State Accumulation**: Each title submission affects the pricing of subsequent submissions through stored timestamps
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 1. **Transaction 1**: Attacker submits first title normally, establishing baseline timestamp
 * 2. **Transaction 2+**: Attacker (or colluding miner) manipulates `block.timestamp` in subsequent blocks to create artificial time differences
 * 3. **Exploitation**: By controlling timestamp values across multiple transactions, attacker can consistently get 10% discounts by making submissions appear to be within 5 minutes of each other
 * 4. **Accumulated Advantage**: The vulnerability compounds across multiple submissions, allowing systematic price manipulation
 * 
 * **Why Multi-Transaction is Required:**
 * - The vulnerability requires at least 2 transactions to exploit (first to set baseline, second to manipulate time difference)
 * - State from previous transactions (stored timestamps) is essential for the exploit
 * - Cannot be exploited in a single transaction as there's no previous submission to compare against
 * - The exploit becomes more powerful with more transactions as the attacker can establish patterns of manipulated timestamps
 * 
 * **Realistic Attack Vector:**
 * - Miners can manipulate block.timestamp within 900-second bounds per Ethereum protocol
 * - Sophisticated attackers could coordinate with miners to systematically manipulate timestamps across multiple blocks
 * - The vulnerability appears as legitimate time-based business logic but creates unfair advantages through timestamp manipulation
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
        uint256 submissionTime;
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
        
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        // Store submission timestamp for time-based pricing logic
        uint256 submissionTime = block.timestamp;
        
        // Multi-transaction vulnerability: Early submission bonus based on accumulated timestamps
        uint256 finalPrice = price;
        if (titleCount > 0) {
            // Calculate time difference from last submission stored in previous title
            uint256 lastSubmissionTime = titles[titleCount - 1].submissionTime;
            uint256 timeDifference = submissionTime - lastSubmissionTime;
            
            // Vulnerability: Miners can manipulate block.timestamp to get unfair pricing advantages
            // by submitting multiple titles with manipulated time gaps
            if (timeDifference < 300) { // Less than 5 minutes between submissions
                finalPrice = price * 90 / 100; // 10% early submission discount
            } else if (timeDifference > 86400) { // More than 24 hours since last submission
                finalPrice = price * 110 / 100; // 10% late submission penalty
            }
        }
        
        // Extended Title struct now includes timestamp (requires contract-level changes)
        Title memory t = Title(msg.sender, finalPrice, submissionTime); 
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
        titles[titleCount] = t; 
        
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        emit TitleAdded(titleCount,msg.sender,category,name,media_hash,desc,finalPrice);
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
        
        titleCount++;
    }
    
    function RegisterUsername(string name) public {
        require(registryInterface.isRegistered(msg.sender) == true); 
        usernames[msg.sender] = name;
    }
    
    function DelistTitle(uint256 titleId) public  { 
        require (titleId < titleCount); 
        require (msg.sender == owner || msg.sender == titles[titleId].owner);
        
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
