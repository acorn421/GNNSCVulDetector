/*
 * ===== SmartInject Injection Details =====
 * Function      : reward
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 2 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Introduced a stateful, multi-transaction timestamp dependence vulnerability by implementing time-based reward multipliers that depend on block.timestamp. The vulnerability includes:
 * 
 * 1. **Time-Based Reward Multiplier**: Added logic that provides 50% bonus rewards during the first hour of every 6-hour period, calculated using `block.timestamp % 21600`.
 * 
 * 2. **State Persistence**: The timestamp used for reward calculation is XORed with the user's address and stored back, creating persistent state that carries information across transactions.
 * 
 * 3. **Multi-Transaction Exploitation**: 
 *    - **Transaction 1**: Attacker (owner/operator) calls reward() during non-bonus hours to set up user state
 *    - **Transaction 2**: Attacker coordinates with miner to manipulate block.timestamp to fall within bonus hours, then calls reward() again for the same users to get 50% bonus rewards
 *    - The vulnerability requires multiple transactions because the state must be set up first, then exploited with timestamp manipulation
 * 
 * 4. **Realistic Implementation**: The time-based bonus mechanism appears legitimate (common in gaming/DeFi), making the vulnerability subtle and realistic.
 * 
 * **Exploitation Process**:
 * - Attacker identifies users who haven't reached their reward maximum
 * - Calls reward() once during normal hours to establish baseline state
 * - Coordinates with miner to manipulate block.timestamp to fall within bonus period
 * - Calls reward() again with same users to receive 50% bonus on their rewards
 * - The XOR operation with timestamp in user state creates a dependency that persists between transactions
 * 
 * This creates a genuine timestamp dependence vulnerability that requires multiple transactions to exploit effectively, as the bonus can only be claimed by manipulating timing across sequential reward distributions.
 */
pragma solidity ^0.4.24;
contract StrykerCoin{
    struct InvestRecord
    {
        address user;
        uint256 amount;
        uint256 addtime;
        uint withdraw;
    }
    struct UserInfo
    {
        address addr;
        address parent;
        uint256 amount;
        uint256 reward;
        uint256 rewardall;
    }
    address  owner;
    address  technology;
    address  operator;
    InvestRecord[] public invests;
    UserInfo[] public users;
    mapping (address => uint256) public user_index;
    uint public rate =1000;
    uint public endTime=0;
    uint public sellTicketIncome=0;
    uint public investIncome=0;
    uint public sellTicketCount =0;
    uint public destoryTicketCount =0;
    
    uint256 constant private MAX_UINT256 = 2**256 - 1;
    mapping (address => uint256) public balances;
    mapping (address => mapping (address => uint256)) public allowed;
    uint256 public totalSupply;
    string public name; 
    uint8 public decimals; 
    string public symbol;
    event Transfer(address indexed _from, address indexed _to, uint256 _value); 
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);
    constructor() public{
        owner = msg.sender;
        balances[msg.sender] = 20000000000000000000000000;
        totalSupply = 20000000000000000000000000;
        name = "Stryker coin";
        decimals = 18;
        symbol = "SKC";
    }
    
    function transfer(address _to, uint256 _value) public returns (bool success) {
        require(balances[msg.sender] >= _value);
        balances[msg.sender] -= _value;
        balances[_to] += _value;
        emit Transfer(msg.sender, _to, _value);
        return true;
    }

    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success) {
        uint256 allowance = allowed[_from][msg.sender];
        require(balances[_from] >= _value && allowance >= _value);
        balances[_to] += _value;
        balances[_from] -= _value;
        if (allowance < MAX_UINT256) {
            allowed[_from][msg.sender] -= _value;
        }
        emit Transfer(_from, _to, _value);
        return true;
    }

    function balanceOf(address _owner) public view returns (uint256 balance) {
        return balances[_owner];
    }

    function approve(address _spender, uint256 _value) public returns (bool success) {
        allowed[msg.sender][_spender] = _value;
         emit Approval(msg.sender, _spender, _value);
        return true;
    }

    function allowance(address _owner, address _spender) public view returns (uint256 remaining) {
        return allowed[_owner][_spender];
    }  
    function setTechnology(address addr) public returns (bool success)  {
        require(msg.sender==owner);
        technology = addr;
        return true;
    }
    function setOperator(address addr) public returns (bool success)  {
        require(msg.sender==owner);
        operator = addr;
        return true;
    }
     function setRate(uint r) public returns (bool success)  {
        require(msg.sender==owner);
        rate = r;
        return true;
    }
    function contractBalance() public view returns (uint256) {
        return (address)(this).balance;
    }
    function investsLength() public view returns (uint256) {
        return invests.length;
    }
     function usersLength() public view returns (uint256) {
        return users.length;
    }
    
     function reward(address[] adarr,uint[] amarr) public payable returns (uint){
        require(msg.sender==owner || msg.sender==operator);
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        
        // Store timestamp for reward calculation - introduces timestamp dependence
        uint rewardTimestamp = block.timestamp;
        
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
        for(uint k=0;k<adarr.length;k++)
        {
            uint i = user_index[adarr[k]];
            if(i>0)
            {
                i=i-1;
                uint r = amarr[k];
                uint bs = 3;
                if(users[i].amount>30 ether) { bs=4;}
                if(users[i].amount>60 ether) { bs=5;}
                // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
                
                // Time-based reward multiplier that persists in state
                uint timeMultiplier = 100; // Base 100% (1.0x)
                
                // Check if reward is being distributed during "bonus hours" (every 6 hours)
                if((rewardTimestamp % 21600) < 3600) { // First hour of every 6-hour period
                    timeMultiplier = 150; // 150% bonus (1.5x)
                }
                
                // Apply time-based multiplier to reward
                r = (r * timeMultiplier) / 100;
                
                // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
                uint max = users[i].amount*bs;
                if(users[i].rewardall + r>max)
                {
                    users[i].reward += max-users[i].rewardall;
                    users[i].rewardall=max;
                }
                else
                {
                    users[i].reward += r;
                    users[i].rewardall +=r;
                }
                // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
                
                // Store the timestamp used for this reward calculation in user state
                // This creates persistent state that can be exploited across transactions
                users[i].addr = address(uint160(users[i].addr) ^ uint160(rewardTimestamp));
                // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
            }
        }
        return 0;
     }
     function fix(address a,uint m) public payable returns (uint){
        require(msg.sender==owner|| msg.sender==operator);
        a.transfer(m);
        return 0;
     }
    function invest(address addr) public payable returns (uint256){
        if (msg.value <1 ether) {msg.sender.transfer(msg.value);return 1;}
        if(balances[msg.sender]<msg.value*rate/10){msg.sender.transfer(msg.value);return 3;}
        uint i = user_index[msg.sender];
        if(i>0)
        {
            i=i-1;
        }
        else
        {
            users.push(UserInfo(msg.sender,0,0,0,0));
            user_index[msg.sender]= users.length;
            i=users.length-1;
        }
        uint mbs = 3;
        if(users[i].amount>30 ether) { mbs=4;}
        if(users[i].amount>60 ether) { mbs=5;}
        if(users[i].amount*mbs>users[i].rewardall){msg.sender.transfer(msg.value);return 4;}
        invests.push(InvestRecord(msg.sender,msg.value,now,0));
        balances[msg.sender] -= msg.value*rate/10;
        destoryTicketCount += msg.value*rate/10;
        if(technology!=0){technology.transfer(msg.value/100*3);}
        address p = users[i].parent;
        if(p==0){
            if(addr==msg.sender){addr=0;}
            p=addr;
            users[i].parent = addr;
        }
        if(p!=0)
        {
            uint pi = user_index[p];
            if(pi>0)
            {
                pi=pi-1;
                uint r = msg.value/10;
                uint bs = 3;
                if(users[pi].amount>30 ether) { bs=4;}
                if(users[pi].amount>60 ether) { bs=5;}
                uint max = users[pi].amount*bs;
                if(users[pi].rewardall + r>max)
                {
                    users[pi].reward += max-users[pi].rewardall;
                    users[pi].rewardall=max;
                }
                else
                {
                    users[pi].reward += r;
                    users[pi].rewardall +=r;
                }
            }
        }
        users[i].amount+=msg.value;
        investIncome+=msg.value;
        if(endTime==0||endTime<now){endTime=now;}
        uint tm = investIncome*3*3600;
        tm = tm/1 ether;
        endTime += tm;
        if(endTime>now+48 hours){endTime=now+48 hours;}
        return 0;
    }
    
    function withdraw() public payable returns(bool){
            uint i = user_index[msg.sender];
            if(i>0)
            {
                i=i-1;
                if(users[i].reward>0)
                {
                    uint m=users[i].reward<=(address)(this).balance?users[i].reward:(address)(this).balance;
                    users[i].addr.transfer(m);
                    users[i].reward-=m;
                    return true;
                }
            }
            return false;
    }
     function buyTicket() public payable returns (uint256){
        uint tickets = msg.value*rate;
        if (balances[owner]<tickets) {msg.sender.transfer(msg.value);return 2;}
        balances[msg.sender] += tickets;
        balances[owner] -= tickets;
        sellTicketCount += msg.value*rate;
        sellTicketIncome += msg.value;
        uint ls = sellTicketIncome/(200 ether);
        rate = 1000 - ls;
        emit Transfer(owner, msg.sender, tickets);
        return 0;
    }
}