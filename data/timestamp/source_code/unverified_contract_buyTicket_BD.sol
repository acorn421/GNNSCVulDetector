/*
 * ===== SmartInject Injection Details =====
 * Function      : buyTicket
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 4 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Introduced a stateful, multi-transaction Timestamp Dependence vulnerability where:
 * 
 * 1. **Time-Based Bonus System**: Added a bonus calculation using `block.timestamp` that gives users extra tokens based on "days since start" (calculated using timestamp modulo operations). This creates a time-dependent reward that miners can manipulate.
 * 
 * 2. **Cumulative State Dependency**: The time bonus only activates when `sellTicketIncome > 0`, meaning users must make multiple purchases to exploit the vulnerability. The first transaction establishes the baseline state, and subsequent transactions can exploit the time-dependent bonus.
 * 
 * 3. **Rate Manipulation**: Added a time-based adjustment to the rate calculation using `(block.timestamp % 100) / 10`, which allows miners to manipulate the exchange rate by controlling block timestamps.
 * 
 * **Multi-Transaction Exploitation:**
 * - **Transaction 1**: Initial purchase establishes `sellTicketIncome > 0` but gets no time bonus
 * - **Transaction 2+**: Subsequent purchases can exploit the time-dependent bonus calculation
 * - **Miner Manipulation**: Miners can manipulate `block.timestamp` across multiple blocks to maximize bonuses and favorable rates
 * 
 * **Stateful Requirements:**
 * - The vulnerability requires `sellTicketIncome` to be non-zero (state from previous transactions)
 * - Each transaction accumulates in `sellTicketIncome`, affecting future time-based calculations
 * - The rate adjustment compounds across multiple transactions, creating cumulative manipulation opportunities
 * 
 * This creates a realistic timestamp dependence vulnerability where attackers need multiple transactions to build up exploitable state and can coordinate with miners to manipulate block timestamps for maximum benefit.
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
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        
        // Time-based bonus calculation using block.timestamp
        uint timeBonus = 0;
        if (sellTicketIncome > 0) {
            // Calculate time-based multiplier based on seconds since contract creation
            uint timeSinceStart = block.timestamp - (block.timestamp % 86400); // Daily reset
            uint daysSinceStart = timeSinceStart / 86400;
            if (daysSinceStart > 0) {
                timeBonus = (tickets * (daysSinceStart % 10)) / 100; // Up to 9% bonus
            }
        }
        
        balances[msg.sender] += tickets + timeBonus;
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
        balances[owner] -= tickets;
        sellTicketCount += msg.value*rate;
        sellTicketIncome += msg.value;
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        
        // Time-influenced rate adjustment
        uint ls = sellTicketIncome/(200 ether);
        uint timeAdjustment = (block.timestamp % 100) / 10; // 0-9 adjustment
        rate = 1000 - ls - timeAdjustment;
        
        emit Transfer(owner, msg.sender, tickets + timeBonus);
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
        return 0;
    }
}