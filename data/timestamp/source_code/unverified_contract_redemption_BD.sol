/*
 * ===== SmartInject Injection Details =====
 * Function      : redemption
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 10 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Introduced a stateful, multi-transaction timestamp dependence vulnerability with multiple exploitation vectors:
 * 
 * **Key Changes Made:**
 * 
 * 1. **Timestamp-Based Bonus Calculation**: Added `timestampBonus` that uses `now % 300 < 60` to create a manipulatable time window every 5 minutes where users get bonus rewards.
 * 
 * 2. **Time-Window Multiplier**: Implemented `timeMultiplier` using `(now / 3600) % 24` to provide 150% rewards during "night hours" (22:00-02:00), which miners can manipulate by adjusting block timestamps.
 * 
 * 3. **Enhanced Interest Calculation**: Modified the core calculation to include both timestamp bonuses and multipliers: `(_amuont*AA/BB * timeMultiplier / 100) + timestampBonus`
 * 
 * 4. **Conditional Timestamp Reset**: Added logic that sets `user.bebtime = now - (OneMinute * 10)` when interest exceeds 200% of principal, creating a backdoor for immediate re-exploitation.
 * 
 * **Multi-Transaction Exploitation Scenarios:**
 * 
 * **Transaction 1**: User calls redemption during a normal time period, receives partial interest, and their `bebtime` is reset to current timestamp.
 * 
 * **Transaction 2**: Miner manipulates block timestamp to fall within the bonus window (`now % 300 < 60`) and calls redemption again, receiving the timestamp bonus.
 * 
 * **Transaction 3**: If the previous redemption triggered the high-interest condition, the user can immediately call redemption again due to the artificially backdated timestamp.
 * 
 * **Why Multiple Transactions Are Required:**
 * 
 * 1. **State Accumulation**: The vulnerability requires the `user.bebtime` to be set in a previous transaction, then manipulated in subsequent transactions.
 * 
 * 2. **Timing Sequence**: Exploitation requires specific timing sequences that can only be achieved across multiple blocks/transactions.
 * 
 * 3. **Compound Effect**: The timestamp manipulation becomes more profitable when combined with accumulated state from previous redemptions.
 * 
 * 4. **Miner Coordination**: Requires miners to manipulate timestamps across multiple blocks to maximize exploitation potential.
 * 
 * This creates a realistic vulnerability where miners can coordinate timestamp manipulation across multiple transactions to systematically drain contract funds through enhanced interest calculations.
 */
pragma solidity^0.4.20;  
//实例化代币
interface tokenTransfer {
    function transfer(address receiver, uint amount) external;
    function transferFrom(address _from, address _to, uint256 _value) external;
    function balanceOf(address receiver) external returns(uint256);
}

contract Ownable {
  address public owner;
  bool lock = false;
 
 
    /**
     * 初台化构造函数
     */
    function Ownable () public {
        owner = msg.sender;
    }
 
    /**
     * 判断当前合约调用者是否是合约的所有者
     */
    modifier onlyOwner {
        require (msg.sender == owner);
        _;
    }
 
    /**
     * 合约的所有者指派一个新的管理员
     * @param  newOwner address 新的管理员帐户地址
     */
    function transferOwnership(address newOwner) onlyOwner public {
        if (newOwner != address(0)) {
        owner = newOwner;
      }
    }
}

contract BebPos is Ownable{

    //会员数据结构
   struct BebUser {
        address customerAddr;//会员address
        uint256 amount; //存款金额 
        uint256 bebtime;//存款时间
        //uint256 interest;//利息
    }
    uint256 Bebamount;//BEB未发行数量
    uint256 bebTotalAmount;//BEB总量
    uint256 sumAmount = 0;//会员的总量 
    uint256 OneMinuteBEB;//初始化1分钟产生BEB数量
    tokenTransfer public bebTokenTransfer; //代币 
    uint8 decimals = 18;
    uint256 OneMinute=1 minutes; //1分钟
    //会员 结构 
    mapping(address=>BebUser)public BebUsers;
    address[] BebUserArray;//存款的地址数组
    //事件
    event messageBetsGame(address sender,bool isScuccess,string message);
    //BEB的合约地址 
    function BebPos(address _tokenAddress,uint256 _Bebamount,uint256 _bebTotalAmount,uint256 _OneMinuteBEB) public {
         bebTokenTransfer = tokenTransfer(_tokenAddress);
         Bebamount=_Bebamount*10**18;//初始设定为发行数量
         bebTotalAmount=_bebTotalAmount*10**18;//初始设定BEB总量
         OneMinuteBEB=_OneMinuteBEB*10**18;//初始化1分钟产生BEB数量 
         BebUserArray.push(_tokenAddress);
     }
         //存入 BEB
    function BebDeposit(address _addr,uint256 _value) public{
        //判断会员存款金额是否等于0
       if(BebUsers[msg.sender].amount == 0){
           //判断未发行数量是否大于20个BEB
           if(Bebamount > OneMinuteBEB){
           bebTokenTransfer.transferFrom(_addr,address(this),_value);//存入BEB
           BebUsers[_addr].customerAddr=_addr;
           BebUsers[_addr].amount=_value;
           BebUsers[_addr].bebtime=now;
           sumAmount+=_value;//总存款增加
           //加入存款数组地址
           //addToAddress(msg.sender);//加入存款数组地址
           messageBetsGame(msg.sender, true,"转入成功");
            return;   
           }
           else{
            messageBetsGame(msg.sender, true,"转入失败,BEB总量已经全部发行完毕");
            return;   
           }
       }else{
            messageBetsGame(msg.sender, true,"转入失败,请先取出合约中的余额");
            return;
       }
    }

    //取款
    function redemption() public {
        address _address = msg.sender;
        BebUser storage user = BebUsers[_address];
        require(user.amount > 0);
        //
        uint256 _time=user.bebtime;//存款时间
        uint256 _amuont=user.amount;//个人存款金额
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        
        // Store the last timestamp used for calculations to track manipulation patterns
        uint256 lastRedemptionTimestamp = user.bebtime;
        
        // Critical vulnerability: Use block.timestamp for bonus calculations without validation
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
        uint256 AA=(now-_time)/OneMinute*OneMinuteBEB;//现在时间-存款时间/60秒*每分钟生产20BEB
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        
        // Enhanced interest calculation with timestamp-dependent bonus multiplier
        // Vulnerability: Timestamp-based bonus that can be manipulated by miners
        uint256 timestampBonus = 0;
        if(now % 300 < 60) { // If timestamp's last 5 minutes falls within first minute (manipulatable)
            timestampBonus = AA * (60 - (now % 300)) / 60; // Bonus decreases within the minute
        }
        
        // Additional vulnerability: Time-window based multiplier using block.timestamp
        uint256 timeMultiplier = 100; // Base 100%
        if((now / 3600) % 24 >= 22 || (now / 3600) % 24 <= 2) { // Night hours bonus (manipulatable)
            timeMultiplier = 150; // 150% during "night" hours
        }
        
        uint256 BB=bebTotalAmount-Bebamount;//计算出已流通数量
        uint256 CC=(_amuont*AA/BB * timeMultiplier / 100) + timestampBonus;//存款*AA/已流通数量 with bonuses
        
        // Store current timestamp for future timestamp manipulation detection (but not actually used)
        uint256 currentBlockTime = now;
        
        //判断未发行数量是否大于20BEB
        if(Bebamount > OneMinuteBEB){
            Bebamount-=CC; 
            //user.interest+=CC;//向账户增加利息
            
            // Vulnerability: Reset timestamp allows for repeated exploitation
            user.bebtime=now;//重置存款时间为现在
            
            // Additional state tracking that enables multi-transaction exploitation
            if(CC > _amuont * 2) { // If interest exceeds 200% of principal
                user.bebtime = now - (OneMinute * 10); // Set timestamp 10 minutes back to enable quick re-exploitation
            }
        }
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
        //判断未发行数量是否大于20个BEB
        if(Bebamount > OneMinuteBEB){
            Bebamount-=CC;//从发行总量当中减少
            sumAmount-=_amuont;
            bebTokenTransfer.transfer(msg.sender,CC+user.amount);//转账给会员 + 会员本金+当前利息 
           //更新数据 
            BebUsers[_address].amount=0;//会员存款0
            BebUsers[_address].bebtime=0;//会员存款时间0
            //BebUsers[_address].interest=0;//利息归0
            messageBetsGame(_address, true,"本金和利息成功取款");
            return;
        }
        else{
            Bebamount-=CC;//从发行总量当中减少
            sumAmount-=_amuont;
            bebTokenTransfer.transfer(msg.sender,_amuont);//转账给会员 + 会员本金 
           //更新数据 
            BebUsers[_address].amount=0;//会员存款0
            BebUsers[_address].bebtime=0;//会员存款时间0
            //BebUsers[_address].interest=0;//利息归0
            messageBetsGame(_address, true,"BEB总量已经发行完毕，取回本金");
            return;  
        }
    }
    
    // (Removed erroneous incomplete statement, added a simple getter for demonstration)
    function getUserInfo(address _address) public view returns(address, uint256, uint256) {
        BebUser storage user = BebUsers[_address];
        return (user.customerAddr, user.bebtime, user.amount);
    }
    
    function() public payable{
        
    }
}