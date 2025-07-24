/*
 * ===== SmartInject Injection Details =====
 * Function      : ChangeRules
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
 * Introduced a stateful, multi-transaction timestamp dependence vulnerability through an emergency rule change mechanism. The vulnerability requires:
 * 
 * 1. **State Variables Added** (assumed to be added to contract): 
 *    - `pendingEmergencyTimestamp`: Stores the timestamp when emergency change was initiated
 *    - `pendingRegCost`, `pendingFirstLevelCost`, `pendingSecondLevelCost`, `pendingParentFee`: Store pending values
 * 
 * 2. **Multi-Transaction Exploitation**:
 *    - **Transaction 1**: Owner initiates emergency change, setting `pendingEmergencyTimestamp = block.timestamp`
 *    - **Transaction 2**: Owner must execute within 5-minute window to apply changes
 * 
 * 3. **Timestamp Dependence Vulnerability**:
 *    - The `block.timestamp` comparison (`block.timestamp <= pendingEmergencyTimestamp + emergencyWindow`) can be manipulated by miners
 *    - Miners can adjust block timestamps within the 15-second tolerance to extend or shorten the emergency window
 *    - This allows bypassing the intended time restrictions for emergency rule changes
 * 
 * 4. **Exploitation Scenarios**:
 *    - **Scenario A**: Miner extends timestamp to allow expired emergency changes to go through
 *    - **Scenario B**: Miner shortens timestamp to make valid emergency changes fail
 *    - **Scenario C**: Sequential manipulation across multiple blocks to control rule change timing
 * 
 * 5. **Why Multi-Transaction is Required**:
 *    - The vulnerability cannot be exploited in a single transaction because the emergency mechanism requires state persistence between calls
 *    - The first transaction sets up the vulnerable state (`pendingEmergencyTimestamp`)
 *    - The second transaction triggers the vulnerable timestamp comparison
 *    - The exploit requires coordination between transactions and potential miner collusion
 * 
 * This creates a realistic timestamp dependence vulnerability that could appear in production code where developers implement time-based security mechanisms without considering timestamp manipulation risks.
 */
pragma solidity ^0.4.10;

contract EtherGame 
{
    address Owner;
    uint public RegCost;
    uint public FirstLevelCost;
    uint public SecondLevelCost;
    uint public ParentFee;
    
    // Added missing state variables for emergency rule change
    uint public pendingEmergencyTimestamp;
    uint public pendingRegCost;
    uint public pendingFirstLevelCost;
    uint public pendingSecondLevelCost;
    uint public pendingParentFee;
    
    struct user
    {
        address parent;
        uint8 level;
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
        // Initialize emergency variables
        pendingEmergencyTimestamp = 0;
        pendingRegCost = 0;
        pendingFirstLevelCost = 0;
        pendingSecondLevelCost = 0;
        pendingParentFee = 0;
    }

    function() payable {}
    
    function NewUser() payable
    {
        if(msg.value < RegCost || Users[msg.sender].parent != 0) 
            revert();
        Users[msg.sender].parent = address(this);
        ListOfUsers.push(msg.sender);
        newuser(msg.sender, address(this));
    }
    
    function NewUser(address addr) payable
    {
        if(msg.value < RegCost || Users[msg.sender].parent != 0 || Users[addr].parent == 0)
            revert();
        if(addr != address(this))
            addr.transfer(RegCost);
        Users[msg.sender].parent = addr;
        ListOfUsers.push(msg.sender);
        newuser(msg.sender, addr);
    }
    
    function BuyLevel() payable
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
    
    function TakeMoney() OnlyOwner
    {
        Owner.transfer(this.balance);
    }
    
    function ChangeOwner(address NewOwner) OnlyOwner
    {
        Owner = NewOwner;
    }
    
    function ChangeRules(uint NewRegCost, uint NewFirsLevelCost, uint NewSecondLevelCost, uint NewParentFee) OnlyOwner
    {
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        // Implement emergency rule changes with timestamp validation
        uint emergencyWindow = 300; // 5 minutes emergency window
        
        // Check if this is an emergency rule change (significant cost increases)
        bool isEmergencyChange = NewRegCost > RegCost * 2 || 
                                NewFirsLevelCost > FirstLevelCost * 2 || 
                                NewSecondLevelCost > SecondLevelCost * 2;
        
        if (isEmergencyChange) {
            // Emergency changes require a 2-step process with timestamp validation
            if (pendingEmergencyTimestamp == 0) {
                // First transaction: Initialize emergency change
                pendingEmergencyTimestamp = block.timestamp;
                pendingRegCost = NewRegCost;
                pendingFirstLevelCost = NewFirsLevelCost;
                pendingSecondLevelCost = NewSecondLevelCost;
                pendingParentFee = NewParentFee;
                return;
            } else {
                // Second transaction: Execute emergency change if within window
                if (block.timestamp <= pendingEmergencyTimestamp + emergencyWindow) {
                    // Apply the pending changes
                    ParentFee = pendingParentFee;
                    FirstLevelCost = pendingFirstLevelCost;
                    SecondLevelCost = pendingSecondLevelCost;
                    RegCost = pendingRegCost;
                    
                    // Reset emergency state
                    pendingEmergencyTimestamp = 0;
                    pendingRegCost = 0;
                    pendingFirstLevelCost = 0;
                    pendingSecondLevelCost = 0;
                    pendingParentFee = 0;
                } else {
                    // Emergency window expired, reset and require restart
                    pendingEmergencyTimestamp = 0;
                    pendingRegCost = 0;
                    pendingFirstLevelCost = 0;
                    pendingSecondLevelCost = 0;
                    pendingParentFee = 0;
                    revert();
                }
            }
        } else {
            // Normal rule changes (no emergency procedure needed)
            ParentFee = NewParentFee;
            FirstLevelCost = NewFirsLevelCost;
            SecondLevelCost = NewSecondLevelCost;
            RegCost = NewRegCost;
        }
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
    }
    
    function Kill() OnlyOwner
    {
        selfdestruct(Owner);
    }

    function UsersNumber() constant returns(uint)
    {
        return ListOfUsers.length;
    }
    
    function UsersList() constant returns(address[])
    {
        return ListOfUsers;
    }

    function MaxChildLevel(address addr) constant returns(uint)
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
