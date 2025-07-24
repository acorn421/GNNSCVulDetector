/*
 * ===== SmartInject Injection Details =====
 * Function      : SchedulePromotionEnd
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 4 issues
 * Retry Count   : 0
 *
 * === Description ===
 * This vulnerability introduces timestamp dependence that requires multiple transactions to exploit. First, an attacker with mining power can schedule a promotion with SchedulePromotionEnd(), then manipulate the block timestamp in subsequent blocks to either extend the promotion period (by setting timestamps before the end time) or force early termination (by jumping timestamps forward). The vulnerability is stateful as it depends on the promotionEndTime mapping and requires the promotion to be active across multiple transactions. Users can purchase titles during the manipulated promotion window, and the price changes persist in contract state between transactions.
 */
pragma solidity ^0.4.18;

contract owned {
    address public owner;

    function owned() public {
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
    
    // === FALLBACK INJECTION: Timestamp Dependence ===
    // These variables/functions are part of the vulnerability injection
    mapping (uint256 => uint256) public promotionEndTime;
    mapping (uint256 => uint256) public originalPrice;
    mapping (uint256 => bool) public isPromotionActive;
    
    event PromotionScheduled(uint256 titleId, uint256 endTime);
    event PromotionEnded(uint256 titleId);
    
    function SchedulePromotionEnd(uint256 titleId, uint256 promotionPrice, uint256 durationInHours) public {
        require(titleId < titleCount);
        require(titles[titleId].owner == msg.sender);
        require(durationInHours > 0 && durationInHours <= 168); // Max 1 week
        
        // Store original price if not already in promotion
        if (!isPromotionActive[titleId]) {
            originalPrice[titleId] = titles[titleId].price;
        }
        
        // Set promotion price
        titles[titleId].price = promotionPrice;
        
        // Schedule end time using block.timestamp
        promotionEndTime[titleId] = block.timestamp + (durationInHours * 1 hours);
        isPromotionActive[titleId] = true;
        
        PromotionScheduled(titleId, promotionEndTime[titleId]);
    }
    
    function EndPromotionIfExpired(uint256 titleId) public {
        require(titleId < titleCount);
        require(isPromotionActive[titleId]);
        
        // Vulnerable: relies on block.timestamp which miners can manipulate
        if (block.timestamp >= promotionEndTime[titleId]) {
            titles[titleId].price = originalPrice[titleId];
            isPromotionActive[titleId] = false;
            
            PromotionEnded(titleId);
        }
    }
    // === END FALLBACK INJECTION ===

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
        require(msg.value == t.price); 
        
        uint256 temp = balances[t.owner];
        balances[t.owner] += msg.value; 
        require(balances[t.owner] > temp);
        
        copiesSold[titleId]++;
        titlesSold[t.owner]++;
        salesEth[t.owner] += msg.value;
        
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
