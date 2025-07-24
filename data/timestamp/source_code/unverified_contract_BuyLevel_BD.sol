/*
 * ===== SmartInject Injection Details =====
 * Function      : BuyLevel
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 1 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Introduced a multi-transaction timestamp dependence vulnerability by adding:
 * 
 * 1. **Time-based Discount System**: Added logic that provides 20% discount during 5-minute windows each hour based on `block.timestamp % 3600 < 300`. This creates predictable time windows that miners can manipulate.
 * 
 * 2. **Cooldown Mechanism**: Implemented a 30-minute cooldown between purchases using `lastPurchaseTime` mapping and `block.timestamp` comparison. This requires state persistence between transactions.
 * 
 * 3. **Multi-Transaction Exploitation Path**:
 *    - **Transaction 1**: User makes initial purchase, `lastPurchaseTime` is set
 *    - **Between Transactions**: Miner manipulates block timestamps to align with discount windows
 *    - **Transaction 2**: User attempts next purchase during manipulated timestamp window to get discount while bypassing cooldown
 * 
 * 4. **Stateful Requirements**: The vulnerability requires:
 *    - Previous purchase timestamp stored in state
 *    - Multiple level purchases to fully exploit
 *    - Time-dependent pricing that miners can influence
 *    - Cooldown enforcement that can be bypassed through timestamp manipulation
 * 
 * The vulnerability is realistic as it mimics common patterns in DeFi and gaming contracts where time-based bonuses and cooldowns are implemented without considering miner timestamp manipulation capabilities.
 */
pragma solidity ^0.4.10;

contract EtherGame 
{
    address Owner;
    uint public RegCost;
    uint public FirstLevelCost;
    uint public SecondLevelCost;
    uint public ParentFee;
    
    struct user
    {
        address parent;
        uint8 level;
    }
    
    address[] ListOfUsers;
    mapping(address=>user) public Users;
    
    // Moved lastPurchaseTime mapping to state variable
    mapping(address => uint) lastPurchaseTime;
    
    event newuser(address User, address Parent);
    event levelup(address User, uint Level);
    
    modifier OnlyOwner() 
    {
        if(msg.sender == Owner) 
        _;
    }
    
    constructor() public
    {
        Owner = msg.sender;
        RegCost = 0 ether;
        FirstLevelCost = 0 ether;
        SecondLevelCost = 0 ether;
        ParentFee = 250;
        Users[address(this)].parent = address(this);
        Users[address(this)].level = 200;
        ListOfUsers.push(address(this));
    }

    function() public payable {}
    
    function NewUser() public payable
    {
        if(msg.value < RegCost || Users[msg.sender].parent != 0) 
            revert();
        Users[msg.sender].parent = address(this);
        ListOfUsers.push(msg.sender);
        emit newuser(msg.sender, address(this));
    }
    
    function NewUser(address addr) public payable
    {
        if(msg.value < RegCost || Users[msg.sender].parent != 0 || Users[addr].parent == 0)
            revert();
        if(addr != address(this))
            addr.transfer(RegCost);
        Users[msg.sender].parent = addr;
        ListOfUsers.push(msg.sender);
        emit newuser(msg.sender, addr);
    }
    
    function BuyLevel() public payable
    {
        uint Price;
        if(Users[msg.sender].level == 0)
            Price = FirstLevelCost;
        else
            Price = uint(8)**Users[msg.sender].level*SecondLevelCost/uint(5)**Users[msg.sender].level*2;
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        
        // Time-based discount system - vulnerable to timestamp manipulation
        if(block.timestamp % 3600 < 300) { // 5-minute window each hour
            Price = Price * 80 / 100; // 20% discount
        }
        
        // Store purchase timestamp for cooldown enforcement
        if(Users[msg.sender].level > 0) {
            require(block.timestamp >= lastPurchaseTime[msg.sender] + 1800); // 30 min cooldown
        }
        
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
        if(msg.value < Price || Users[msg.sender].parent == 0)
            revert();
        address ToTransfer = Users[msg.sender].parent;
        uint Level = Users[msg.sender].level + 1;
        while(Users[ToTransfer].level < Level)
            ToTransfer = Users[ToTransfer].parent;
        if(ToTransfer != address(this))
        {
            ToTransfer.transfer(Price/1000*(1000-ParentFee));
            ToTransfer = Users[ToTransfer].parent;
            if(ToTransfer != address(this) && ParentFee != 0)
                ToTransfer.transfer(Price/1000*ParentFee);
        }
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        
        lastPurchaseTime[msg.sender] = block.timestamp;
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
        Users[msg.sender].level++;
        emit levelup(msg.sender, Level);
    }
    
    function TakeMoney() public OnlyOwner
    {
        Owner.transfer(address(this).balance);
    }
    
    function ChangeOwner(address NewOwner) public OnlyOwner
    {
        Owner = NewOwner;
    }
    
    function ChangeRules(uint NewRegCost, uint NewFirsLevelCost, uint NewSecondLevelCost, uint NewParentFee) public OnlyOwner
    {
        ParentFee = NewParentFee;
        FirstLevelCost = NewFirsLevelCost;
        SecondLevelCost = NewSecondLevelCost;
        RegCost = NewRegCost;
    }
    
    function Kill() public OnlyOwner
    {
        selfdestruct(Owner);
    }

    function UsersNumber() public constant returns(uint)
    {
        return ListOfUsers.length;
    }
    
    function UsersList() public constant returns(address[])
    {
        return ListOfUsers;
    }

    function MaxChildLevel(address addr) public constant returns(uint)
    {
        uint MaxLevel = 0;
        uint Level;
        address child;
        for(uint i=0;i<ListOfUsers.length;i++)
        {
            child = ListOfUsers[i];
            Level = Users[child].level;
            while(child != address(this) && Users[child].parent != addr)
                child = Users[child].parent;
            if(child != address(this) && Level > MaxLevel)
                MaxLevel = Level;
        }
        return MaxLevel;
    }
    
}
