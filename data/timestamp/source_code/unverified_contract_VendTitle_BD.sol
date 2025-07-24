/*
 * ===== SmartInject Injection Details =====
 * Function      : VendTitle
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
 * Introduced a stateful, multi-transaction timestamp dependence vulnerability through time-based pricing and volume discounts. The vulnerability requires state variables `dailySalesDay` and `dailySalesCount` to track daily sales per title. The function now calculates dynamic pricing based on:
 * 
 * 1. **Time-based discount**: 10% discount after 6 hours from day start (uses block.timestamp % 86400 > 21600)
 * 2. **Accumulated volume discounts**: Additional discounts based on daily sales count that builds up across transactions
 * 3. **Daily reset mechanism**: Sales counter resets each day using block.timestamp / 86400
 * 
 * **Multi-Transaction Exploitation Process:**
 * 1. **Transaction 1-4**: Early buyers make purchases to accumulate dailySalesCount[titleId] 
 * 2. **Transaction 5**: Attacker waits for dailySalesCount to reach 5 for 8% volume discount
 * 3. **Transaction 6+**: Attacker waits for count to reach 10 for 15% volume discount
 * 4. **Timing Attack**: Attacker can manipulate block.timestamp (within ~15 second tolerance) to hit the 6-hour discount threshold
 * 5. **Combined Exploit**: Maximum savings achieved by combining time-based (10%) + volume-based (15%) discounts = 23.5% total discount
 * 
 * **Why Multi-Transaction is Required:**
 * - Volume discounts only activate after accumulated sales from previous transactions
 * - Attacker needs other users' transactions to build up the daily sales count
 * - The daily reset mechanism requires tracking state across multiple days/transactions
 * - Timing manipulation is more effective when combined with accumulated volume state
 * 
 * **Realistic Attack Scenario:**
 * An attacker could monitor pending transactions, wait for daily sales to accumulate, then use miner collaboration or precise timing to purchase at the optimal timestamp for maximum discount combination.
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

    // FIX: Declare necessary mappings for daily sales tracking
    mapping (uint256 => uint256) public dailySalesDay;
    mapping (uint256 => uint256) public dailySalesCount;

    function AddCategory(string categoryName) public onlyOwner { 
        CategoryAdded(categoriesCount,categoryName);
        categoriesCount++;
    }
    
    function RemoveCategory(uint256 id) public onlyOwner { 
        CategoryDeleted(id);
    }
    
    function SetRegistrationContract(address registryAddress) public onlyOwner { 
        registryInterface = Registration(registryAddress);
        
    }
    
    function AddTitle(uint256 category,string name,string media_hash,string desc,uint256 price) public { 
        require(registryInterface.isRegistered(msg.sender) == true); 
        
        Title memory t = Title(msg.sender,price); 
        titles[titleCount] = t; 
        
        TitleAdded(titleCount,msg.sender,category,name,media_hash,desc,price);
        
        titleCount++;
    }
    
    function RegisterUsername(string name) public {
        require(registryInterface.isRegistered(msg.sender) == true); 
        usernames[msg.sender] = name;
    }
    
    function DelistTitle(uint256 titleId) public  { 
        require (titleId < titleCount); 
        require (msg.sender == owner || msg.sender == titles[titleId].owner);
        
        TitleDelisted(titleId);
        
    }
    
    function ApproveTitle(uint256 titleId) public onlyOwner { 
        require (titleId < titleCount); 
        
        TitleApproved(titleId);
    }
    
    function EditTile(uint256 id,uint256 category,string name,string media_hash,string desc,uint256 price) public { 
        require (id < titleCount);
        require(titles[id].owner == msg.sender);
        
        titles[id].price = price;
        
        TitleUpdated(id,category, name, media_hash, desc, price);

    }
    
    function VendTitle(uint256 titleId) public payable {
        require (titleId < titleCount); 
        Title storage t = titles[titleId]; 
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        
        // Track daily sales for volume-based discounts
        uint256 currentDay = block.timestamp / 86400; // 24 hours in seconds
        if (dailySalesDay[titleId] != currentDay) {
            dailySalesDay[titleId] = currentDay;
            dailySalesCount[titleId] = 0;
        }
        
        // Apply time-based pricing with accumulated daily sales bonus
        uint256 finalPrice = t.price;
        
        // 10% discount for purchases made after 6 hours from day start
        if ((block.timestamp % 86400) > 21600) {
            finalPrice = (finalPrice * 90) / 100;
        }
        
        // Additional volume discount based on accumulated daily sales
        if (dailySalesCount[titleId] >= 10) {
            finalPrice = (finalPrice * 85) / 100; // Extra 15% off for high volume days
        } else if (dailySalesCount[titleId] >= 5) {
            finalPrice = (finalPrice * 92) / 100; // Extra 8% off for medium volume days
        }
        
        require(msg.value == finalPrice); 
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
        
        uint256 temp = balances[t.owner];
        balances[t.owner] += msg.value; 
        require(balances[t.owner] > temp);
        
        copiesSold[titleId]++;
        titlesSold[t.owner]++;
        salesEth[t.owner] += msg.value;
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        dailySalesCount[titleId]++;
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
        
        TitlePurchased(msg.sender, titleId);
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
