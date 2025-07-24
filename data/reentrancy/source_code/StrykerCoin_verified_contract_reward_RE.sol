/*
 * ===== SmartInject Injection Details =====
 * Function      : reward
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 1 findings
 * Total Found   : 2 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 *
 * === Description ===
 * **VULNERABILITY INJECTION ANALYSIS**
 * 
 * **1. Specific Changes Made:**
 * - Added external call using `adarr[k].call()` to notify users about rewards before state updates
 * - Calculated reward amount (`rewardToAdd`) before the external call
 * - Moved state updates (`users[i].reward` and `users[i].rewardall`) to occur AFTER the external call
 * - Added null address check to prevent calling address(0)
 * 
 * **2. Multi-Transaction Exploitation Sequence:**
 * This vulnerability requires a sophisticated multi-transaction attack:
 * 
 * **Phase 1 - Setup (Transaction 1):**
 * - Attacker deploys malicious contract with `onRewardReceived()` function
 * - Attacker becomes a user in the system with some initial investment
 * - Attacker's contract address is registered in the system
 * 
 * **Phase 2 - State Accumulation (Transactions 2-N):**
 * - Legitimate reward calls occur, building up the attacker's reward balance
 * - Each call to `reward()` with attacker's address triggers the external call
 * - During reentrancy, attacker can call other functions (like `withdraw()`) before state is updated
 * - The attacker can drain rewards multiple times because state updates happen after external calls
 * 
 * **Phase 3 - Exploitation (Transaction N+1):**
 * - When `reward()` is called with attacker's address in the array:
 *   1. External call to attacker's `onRewardReceived()` is made
 *   2. Attacker's contract re-enters and calls `withdraw()` function
 *   3. Since state hasn't been updated yet, old reward values are used
 *   4. Attacker can withdraw rewards multiple times in a single transaction
 *   5. State is finally updated after the external call returns
 * 
 * **3. Why Multiple Transactions Are Required:**
 * - **State Accumulation**: The vulnerability depends on accumulated reward state from previous transactions
 * - **Trust Building**: The system needs to build up reward balances over time to make exploitation profitable
 * - **External Call Dependency**: The reentrancy only triggers when the external call mechanism is invoked
 * - **Realistic Attack Pattern**: Real attackers would need time to position themselves and accumulate significant rewards before exploitation
 * 
 * **4. Vulnerability Mechanics:**
 * - **Check-Effects-Interactions Violation**: External calls occur before state updates
 * - **Persistent State Dependency**: Exploitation depends on `users[i].reward` values accumulated over time
 * - **Multi-Call Amplification**: Each element in the array can trigger reentrancy
 * - **Cross-Function Interaction**: Reentrancy can target other functions like `withdraw()` that depend on the same state
 * 
 * This creates a realistic, stateful reentrancy vulnerability that mirrors real-world attack patterns seen in production smart contracts.
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
                // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
                
                // Calculate reward amount before state update
                uint rewardToAdd = 0;
                if(users[i].rewardall + r>max)
                {
                    rewardToAdd = max-users[i].rewardall;
                }
                else
                {
                    rewardToAdd = r;
                }
                
                // External call for reward notification - VULNERABILITY: Called before state update
                if(rewardToAdd > 0 && adarr[k] != address(0)) {
                    // Call user's contract to notify of reward (potential reentrancy point)
                    bool success = adarr[k].call(bytes4(keccak256("onRewardReceived(uint256)")), rewardToAdd);
                    // Continue processing regardless of call success
                }
                
                // State updates occur AFTER external call - VULNERABLE to reentrancy
                // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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