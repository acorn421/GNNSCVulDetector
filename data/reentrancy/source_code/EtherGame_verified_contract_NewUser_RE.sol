/*
 * ===== SmartInject Injection Details =====
 * Function      : NewUser
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 3 findings
 * Total Found   : 4 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-eth (SWC-107)
 * 2. reentrancy-benign (SWC-107)
 * 3. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Injected a stateful, multi-transaction reentrancy vulnerability by adding an external call to msg.sender before state updates are complete. The vulnerability requires multiple transactions to exploit:
 * 
 * **Transaction 1 (Setup):** Attacker deploys a malicious contract with onUserRegistered() callback function that can call back into NewUser() or other contract functions.
 * 
 * **Transaction 2 (Exploit):** Attacker calls NewUser() from their malicious contract. The external call to onUserRegistered() occurs before Users[msg.sender].parent and ListOfUsers are updated, allowing the callback to:
 * - Re-enter NewUser() while Users[msg.sender].parent is still 0 (bypassing the duplicate registration check)
 * - Manipulate contract state during the reentrancy window
 * - Access inconsistent state where the caller appears unregistered but has paid registration fees
 * 
 * **Multi-Transaction Nature:** The vulnerability requires:
 * 1. First transaction to deploy the malicious contract with callback
 * 2. Second transaction to trigger the registration with reentrancy
 * 3. The persistent state changes from successful exploitation affect future contract interactions
 * 
 * **State Persistence:** The Users mapping and ListOfUsers array maintain the exploited state across transactions, potentially allowing multiple registrations or state corruption that persists beyond the initial exploit transaction.
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
    
    event newuser(address User, address Parent);
    event levelup(address User, uint Level);
    
    modifier OnlyOwner() 
    {
        if(msg.sender == Owner) 
        _;
    }
    
    function EtherGame()
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

    function() payable {}
    
    function NewUser() payable
    {
        if(msg.value < RegCost || Users[msg.sender].parent != 0) 
            throw;
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // External call to notify user about registration - VULNERABILITY INJECTION
        // This allows reentrancy before state updates are complete
        if(msg.sender != address(this)) {
            msg.sender.call.value(0)(bytes4(keccak256("onUserRegistered()")));
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        Users[msg.sender].parent = address(this);
        ListOfUsers.push(msg.sender);
        newuser(msg.sender, address(this));
    }
    
    function NewUser(address addr) payable
    {
        if(msg.value < RegCost || Users[msg.sender].parent != 0 || Users[addr].parent == 0)
            throw;
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
            throw;
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
        ParentFee = NewParentFee;
        FirstLevelCost = NewFirsLevelCost;
        SecondLevelCost = NewSecondLevelCost;
        RegCost = NewRegCost;
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