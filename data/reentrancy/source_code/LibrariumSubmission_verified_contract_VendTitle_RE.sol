/*
 * ===== SmartInject Injection Details =====
 * Function      : VendTitle
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 3 findings
 * Total Found   : 6 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-eth (SWC-107)
 * 2. reentrancy-benign (SWC-107)
 * 3. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by:
 * 
 * 1. **Added State Variables**: 
 *    - `titleNotificationSent` mapping to track notification status per title
 *    - `pendingPurchases` mapping to track pending purchase count per title
 * 
 * 2. **Introduced External Call**: Added a call to `t.owner.call.value(0)()` to notify the title owner about purchases, which occurs BEFORE critical state updates
 * 
 * 3. **State-Dependent Logic**: The notification is only sent once per title (checked via `titleNotificationSent[titleId]`), creating state dependency across transactions
 * 
 * 4. **Multi-Transaction Exploitation Path**:
 *    - **Transaction 1**: First buyer calls VendTitle, triggers external call to malicious owner contract
 *    - **Malicious Contract**: During callback, calls VendTitle again before first transaction completes
 *    - **Transaction 2**: Second reentrancy call bypasses the notification check (already set to true) but still increments pendingPurchases
 *    - **Result**: Multiple purchases can occur before balance updates, allowing attacker to drain funds
 * 
 * 5. **Why Multi-Transaction is Required**:
 *    - The vulnerability relies on the `titleNotificationSent` state being set in the first transaction
 *    - Subsequent reentrancy calls in the same transaction benefit from this state change
 *    - The accumulated effect of multiple `pendingPurchases` increments creates the exploitable condition
 *    - Each reentrant call adds to the pending count, but balance updates are delayed until after all calls complete
 * 
 * 6. **Exploitation Scenario**:
 *    - Attacker creates a malicious title owner contract
 *    - First legitimate purchase triggers notification to malicious contract
 *    - Malicious contract reenters VendTitle multiple times during callback
 *    - Each reentrancy increases pendingPurchases but delays balance updates
 *    - Results in multiple sales being processed but payment only received once
 * 
 * This creates a realistic vulnerability where the external notification mechanism enables stateful reentrancy attacks that require multiple transaction contexts to exploit effectively.
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
    
    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
mapping (uint256 => bool) public titleNotificationSent; // Track if owner has been notified
    mapping (uint256 => uint256) public pendingPurchases; // Track pending purchases
    
    function VendTitle(uint256 titleId) public payable {
// ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        require (titleId < titleCount); 
        Title storage t = titles[titleId]; 
        require(msg.value == t.price); 
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // Mark this purchase as pending
        pendingPurchases[titleId]++;
        
        // Notify the title owner about the purchase (external call vulnerability)
        if (!titleNotificationSent[titleId]) {
            titleNotificationSent[titleId] = true;
            // External call to title owner's contract for notification
            bool success = t.owner.call.value(0)(abi.encodeWithSignature("onTitlePurchased(uint256,address)", titleId, msg.sender));
            // Continue regardless of success
        }
        
        // Critical state updates occur AFTER external call
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        uint256 temp = balances[t.owner];
        balances[t.owner] += msg.value; 
        require(balances[t.owner] > temp);
        
        copiesSold[titleId]++;
        titlesSold[t.owner]++;
        salesEth[t.owner] += msg.value;
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // Clear pending purchase
        pendingPurchases[titleId]--;
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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