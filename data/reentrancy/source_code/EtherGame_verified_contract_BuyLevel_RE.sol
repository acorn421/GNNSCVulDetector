/*
 * ===== SmartInject Injection Details =====
 * Function      : BuyLevel
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
 * 1. reentrancy-eth (SWC-107)
 * 2. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding a 'processing' state flag and modifying external call patterns. The vulnerability requires multiple transactions to exploit:
 * 
 * 1. **Processing State Addition**: Added a 'processing' boolean flag that persists between transactions, creating stateful vulnerability conditions.
 * 
 * 2. **External Call Modification**: Changed transfer() calls to call() which allows callbacks to malicious contracts, enabling reentrancy entry points.
 * 
 * 3. **Multi-Transaction Exploitation Path**:
 *    - Transaction 1: Attacker calls BuyLevel(), sets processing=true, triggers callback to malicious contract
 *    - During callback: Malicious contract calls BuyLevel() again, finds processing=true, completes with level increment
 *    - Transaction 2: Original call completes, increments level again due to processing state
 * 
 * 4. **State Persistence**: The processing flag maintains state between transactions, allowing incomplete operations to be exploited in subsequent calls.
 * 
 * 5. **Realistic Integration**: The processing flag appears as a legitimate mechanism to handle ongoing transactions but creates a window for stateful reentrancy attacks.
 * 
 * The vulnerability requires multiple transactions because the processing state must be set in one transaction and exploited in another, making it impossible to exploit atomically within a single transaction.
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
        bool processing;
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
        Users[address(this)].processing = false;
        ListOfUsers.push(address(this));
    }

    function() payable public {}
    
    function NewUser() public payable
    {
        if(msg.value < RegCost || Users[msg.sender].parent != 0) 
            revert();
        Users[msg.sender].parent = address(this);
        Users[msg.sender].level = 0;
        Users[msg.sender].processing = false;
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
        Users[msg.sender].level = 0;
        Users[msg.sender].processing = false;
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
        if(msg.value < Price || Users[msg.sender].parent == 0)
            revert();
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        address ToTransfer = Users[msg.sender].parent;
        uint Level = Users[msg.sender].level + 1;
        while(Users[ToTransfer].level < Level)
            ToTransfer = Users[ToTransfer].parent;
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Add processing state to track ongoing transactions
        if(Users[msg.sender].processing) {
            // Allow completion of previously started transaction
            Users[msg.sender].processing = false;
            Users[msg.sender].level++;
            emit levelup(msg.sender, Level);
            return;
        }
        
        Users[msg.sender].processing = true;
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        if(ToTransfer != address(this))
        {
            // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
            // External call with callback mechanism - potential reentrancy point
            if(ToTransfer.call.value(Price/1000*(1000-ParentFee))("") ) {
                ToTransfer = Users[ToTransfer].parent;
                if(ToTransfer != address(this) && ParentFee != 0)
                    ToTransfer.call.value(Price/1000*ParentFee)("");
            }
        }
        
        // State update moved after external calls and depends on processing flag
        if(Users[msg.sender].processing) {
            Users[msg.sender].processing = false;
            Users[msg.sender].level++;
            emit levelup(msg.sender, Level);
        }
            // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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
