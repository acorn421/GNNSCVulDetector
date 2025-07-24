/*
 * ===== SmartInject Injection Details =====
 * Function      : AddTitle
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 2 findings
 * Total Found   : 3 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-benign (SWC-107)
 * 2. reentrancy-events (SWC-107)
 *
 * === Description ===
 * This modification introduces a stateful, multi-transaction reentrancy vulnerability by:
 * 
 * **1. Specific Changes Made:**
 * - Added an additional external call to `registryInterface.isRegistered(msg.sender)` within a conditional block for "enhanced category validation"
 * - This creates a second external call point that can be exploited for reentrancy
 * - The state updates (`titles[titleCount] = t` and `titleCount++`) still occur after the external calls, violating the Checks-Effects-Interactions pattern
 * 
 * **2. Multi-Transaction Exploitation Pattern:**
 * The vulnerability requires multiple transactions to exploit effectively:
 * 
 * **Transaction 1 (Setup):** Attacker deploys a malicious contract that implements the Registration interface and sets it as the registry through social engineering or if they gain temporary access.
 * 
 * **Transaction 2 (Initial Call):** Attacker calls AddTitle with category > 0, which triggers the external call to their malicious registry contract.
 * 
 * **Transaction 3+ (Reentrancy Exploitation):** During the external call, the malicious registry contract calls back into AddTitle multiple times before the original call completes. Each reentrant call:
 * - Sees the same `titleCount` value (not yet incremented)
 * - Assigns multiple titles to the same ID
 * - Creates state inconsistencies that persist across transactions
 * 
 * **Transaction N (Exploitation):** In subsequent transactions, the attacker exploits the corrupted state where multiple titles have the same ID, potentially allowing them to manipulate ownership or pricing of titles they don't own.
 * 
 * **3. Why Multiple Transactions Are Required:**
 * - **State Accumulation:** The vulnerability creates persistent state corruption (multiple titles with same ID) that builds up over multiple calls
 * - **Cross-Transaction Dependencies:** The exploitation depends on the corrupted state persisting between transactions and being exploitable in future function calls
 * - **Realistic Attack Vector:** Real attackers would need multiple transactions to set up their malicious contracts, perform the reentrancy attack, and then exploit the resulting state corruption
 * - **Time-Based Exploitation:** The attacker needs time between transactions to analyze the corrupted state and plan their exploitation strategy
 * 
 * This creates a realistic, stateful reentrancy vulnerability that mirrors real-world attack patterns where vulnerabilities are exploited across multiple blocks and transactions.
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
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Enhanced category validation through external registry call
        // This introduces a reentrancy vulnerability point
        if (category > 0) {
            bool categoryValid = registryInterface.isRegistered(msg.sender);
            require(categoryValid == true);
        }
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        
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