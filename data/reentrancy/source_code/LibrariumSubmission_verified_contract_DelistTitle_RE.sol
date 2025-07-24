/*
 * ===== SmartInject Injection Details =====
 * Function      : DelistTitle
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 3 findings
 * Total Found   : 7 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-benign (SWC-107)
 * 3. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by implementing a two-phase delisting process:
 * 
 * 1. **State Variables Added**: 
 *    - `delistingInProgress[titleId]` tracks ongoing delisting operations
 *    - `delistingPhase[titleId]` tracks which phase of delisting process is active
 * 
 * 2. **Multi-Transaction Exploitation**:
 *    - **Transaction 1**: First call to DelistTitle sets `delistingPhase[titleId] = 1` and marks `delistingInProgress[titleId] = true`
 *    - **Transaction 2**: Second call triggers the external call to registryInterface, creating reentrancy opportunity
 *    - **Exploitation**: During the external call, an attacker can re-enter and exploit the inconsistent state where the title is marked for delisting but not yet deleted
 * 
 * 3. **Reentrancy Vector**:
 *    - The `registryInterface.call()` creates an external call that can be exploited
 *    - State changes occur both before and after the external call
 *    - Between the external call and final state cleanup, the contract is in an inconsistent state
 *    - An attacker controlling the registry contract can re-enter and perform operations on titles that should be delisted
 * 
 * 4. **Exploitation Scenario**:
 *    - Attacker deploys malicious registry contract
 *    - Calls DelistTitle twice to reach the external call phase
 *    - During the external call, malicious registry re-enters the contract
 *    - Can exploit the inconsistent state where `delistingInProgress[titleId] = true` but title still exists
 *    - Could potentially manipulate title ownership, pricing, or other operations before final deletion
 * 
 * This vulnerability requires multiple transactions to set up the exploit state and demonstrates realistic reentrancy patterns found in production contracts.
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

    // NEW: State variables for delisting tracking
    mapping (uint256 => bool) public delistingInProgress;
    mapping (uint256 => uint256) public delistingPhase;
    
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
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // Mark title as delisting in progress
        delistingInProgress[titleId] = true;
        
        // If this is the second call for the same title, complete the delisting
        if (delistingPhase[titleId] == 1) {
            // Notify external registry before final delisting
            if (registryInterface != Registration(0)) {
                registryInterface.call(bytes4(keccak256("titleDelisted(uint256)")), titleId);
            }
            
            // Complete delisting after external call
            delete titles[titleId];
            delistingInProgress[titleId] = false;
            delistingPhase[titleId] = 0;
            
            TitleDelisted(titleId);
        } else {
            // First call - initiate delisting phase
            delistingPhase[titleId] = 1;
        }
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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