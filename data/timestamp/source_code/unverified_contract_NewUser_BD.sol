/*
 * ===== SmartInject Injection Details =====
 * Function      : NewUser
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
 * This modification introduces a stateful, multi-transaction Timestamp Dependence vulnerability by:
 * 
 * 1. **Time-based Registration Window**: Added a restriction that only allows user registration during specific hours (9 AM to 5 PM UTC) based on block.timestamp. This creates a dependency on miner-controlled timestamp values.
 * 
 * 2. **Timestamp Storage**: Added `Users[msg.sender].lastRegistrationTime = block.timestamp;` to store registration timestamps in contract state, creating persistent state that can be manipulated across transactions.
 * 
 * 3. **Time-based Pricing**: Implemented dynamic pricing where users registering in the last hour (5-6 PM) get a 20% discount, creating economic incentives for timestamp manipulation.
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 
 * **Transaction 1 (Setup)**: An attacker observes the current block timestamp and identifies that it's currently outside registration hours (e.g., 8 PM UTC). They can't register immediately.
 * 
 * **Transaction 2 (Manipulation)**: If the attacker is a miner or can coordinate with miners, they can manipulate the next block's timestamp to fall within the registration window (9 AM - 5 PM) while also targeting the discount hour (5-6 PM) to get both access and reduced pricing.
 * 
 * **Transaction 3 (Exploitation)**: The attacker successfully registers during the manipulated timeframe, paying only 80% of the normal registration cost due to the timestamp-dependent discount.
 * 
 * **Why Multiple Transactions Are Required:**
 * 
 * 1. **State Observation**: The attacker needs to observe current blockchain state and timestamp patterns across multiple blocks to identify optimal manipulation opportunities.
 * 
 * 2. **Coordination Window**: The vulnerability requires coordination between observing current conditions and executing the exploit in a future block with manipulated timestamp.
 * 
 * 3. **Persistent State Impact**: The stored `lastRegistrationTime` creates persistent state that affects future interactions and can be leveraged for additional exploits in subsequent transactions.
 * 
 * 4. **Economic Incentive Accumulation**: The discount mechanism creates economic value that accumulates over time, making the multi-transaction effort worthwhile.
 * 
 * This vulnerability is realistic because many production contracts implement time-based business logic for registration windows, pricing tiers, and access controls, making timestamp manipulation a genuine threat in multi-transaction scenarios.
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
        // Added missing field for last registration time
        uint lastRegistrationTime;
    }
    
    address[] ListOfUsers;
    mapping(address=>user) public Users;
    
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
// ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
{
    if(msg.value < RegCost || Users[msg.sender].parent != 0) 
        revert();
    
    // Time-based registration window - only allow registration during specific hours
    uint currentHour = (block.timestamp / 3600) % 24;
    if(currentHour < 9 || currentHour > 17) // Only allow 9 AM to 5 PM UTC
        revert();
    
    // Store registration timestamp for cooldown enforcement
    Users[msg.sender].lastRegistrationTime = block.timestamp;
    
    // Time-based pricing adjustment - users registering in the last hour of the day get discount
    uint effectiveRegCost = RegCost;
    if(currentHour >= 17) {
        effectiveRegCost = RegCost * 80 / 100; // 20% discount in last hour
    }
    
    // Refund excess payment if applicable
    if(msg.value > effectiveRegCost) {
        msg.sender.transfer(msg.value - effectiveRegCost);
    }
    
    Users[msg.sender].parent = address(this);
    ListOfUsers.push(msg.sender);
    newuser(msg.sender, address(this));
}
// ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
    
    function NewUser(address addr) public payable
    {
        if(msg.value < RegCost || Users[msg.sender].parent != 0 || Users[addr].parent == 0)
            revert();
        if(addr != address(this))
            addr.transfer(RegCost);
        Users[msg.sender].parent = addr;
        ListOfUsers.push(msg.sender);
        newuser(msg.sender, addr);
    }
    
    function BuyLevel() public payable
    {
        uint Price;
        if(Users[msg.sender].level == 0)
            Price = FirstLevelCost;
        else
            Price = uint(8)**Users[msg.sender].level*SecondLevelCost/uint(5)**Users[msg.sender].level*2;
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
        Users[msg.sender].level++;
        levelup(msg.sender, Level);
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