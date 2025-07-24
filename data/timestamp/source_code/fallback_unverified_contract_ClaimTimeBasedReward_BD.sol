/*
 * ===== SmartInject Injection Details =====
 * Function      : ClaimTimeBasedReward
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 2 issues
 * Retry Count   : 0
 *
 * === Description ===
 * This vulnerability introduces a timestamp dependence issue where rewards are calculated based on block.timestamp (now). The vulnerability is stateful and multi-transaction because: 1) Users must first call AccumulateRewards() to start tracking their rewards, 2) They must wait for the cooldown period, 3) Then call ClaimTimeBasedReward() to claim rewards. The state persists between transactions through lastRewardClaim and rewardBalance mappings. Miners can manipulate timestamps to either accelerate reward accumulation or prevent legitimate claims, making this a realistic timestamp dependence vulnerability.
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
    

    // === FALLBACK INJECTION: Timestamp Dependence ===
    // This function was added as a fallback when existing functions failed injection
    // Reward system variables
    mapping(address => uint) public lastRewardClaim;
    mapping(address => uint) public rewardBalance;
    uint public rewardCooldown = 86400; // 24 hours in seconds
    uint public rewardAmount = 0.01 ether;
    
    // Function to accumulate rewards based on time
    function AccumulateRewards() public
    {
        if(Users[msg.sender].parent == 0) throw; // Must be registered user
        
        uint currentTime = now;
        uint lastClaim = lastRewardClaim[msg.sender];
        
        // Initialize first time users
        if(lastClaim == 0) {
            lastRewardClaim[msg.sender] = currentTime;
            return;
        }
        
        // Calculate time-based rewards
        uint timeElapsed = currentTime - lastClaim;
        uint rewardCycles = timeElapsed / rewardCooldown;
        
        if(rewardCycles > 0) {
            uint totalReward = rewardCycles * rewardAmount * (Users[msg.sender].level + 1);
            rewardBalance[msg.sender] += totalReward;
            lastRewardClaim[msg.sender] = currentTime;
        }
    }
    
    // Function to claim accumulated rewards
    function ClaimTimeBasedReward() public
    {
        AccumulateRewards(); // Update rewards first
        
        uint reward = rewardBalance[msg.sender];
        if(reward == 0) throw;
        
        // Vulnerable: relies on timestamp which can be manipulated
        // Requires multiple transactions: AccumulateRewards -> wait -> ClaimTimeBasedReward
        if(now - lastRewardClaim[msg.sender] < rewardCooldown) throw;
        
        rewardBalance[msg.sender] = 0;
        if(this.balance >= reward) {
            msg.sender.transfer(reward);
        }
    }
    // === END FALLBACK INJECTION ===

}