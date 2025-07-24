/*
 * ===== SmartInject Injection Details =====
 * Function      : getUserProfit
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 12 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Introduced a stateful, multi-transaction timestamp dependence vulnerability where:
 * 
 * 1. **State Modification**: Changed function from `view` to non-view, allowing state modifications that persist between transactions
 * 
 * 2. **Timestamp Caching**: Added logic that modifies `user.bebtime` based on current timestamp, creating cached timestamp values that affect future profit calculations
 * 
 * 3. **Block-Based Multiplier**: Implemented a timestamp-dependent multiplier based on `(now / OneMinute) % 2` that creates different profit calculations depending on when the transaction is mined
 * 
 * 4. **Persistent State Changes**: The function now modifies `Bebamount` when bonus conditions are met, creating state changes that carry over to subsequent transactions
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 
 * **Transaction 1**: Attacker calls `getUserProfit` during an odd minute block (timeMultiplier = 1000)
 * - Function caches a normalized timestamp in `user.bebtime`  
 * - No bonus applied, `Bebamount` unchanged
 * - Profit calculated with base multiplier
 * 
 * **Transaction 2**: Attacker waits and calls `getUserProfit` during an even minute block (timeMultiplier = 1200)
 * - Function uses the cached timestamp from Transaction 1
 * - 20% bonus multiplier applied due to even minute block timing
 * - `Bebamount` is reduced, affecting the denominator `B` for future calculations
 * - Higher profit returned due to both multiplier and reduced denominator
 * 
 * **Transaction 3**: Subsequent calls now benefit from the reduced `Bebamount` state
 * - The state modification from Transaction 2 persists
 * - All future profit calculations use the modified `Bebamount` value
 * - Compounding effect where timestamp manipulation in one transaction benefits all future transactions
 * 
 * **Why Multi-Transaction Required:**
 * - The vulnerability requires timing transactions to specific block timestamps
 * - State modifications (cached timestamps, reduced `Bebamount`) from earlier transactions enable exploitation in later transactions
 * - The cached `user.bebtime` value creates a dependency chain across multiple function calls
 * - Miner timestamp manipulation in one transaction sets up favorable conditions for exploitation in subsequent transactions
 */
pragma solidity^0.4.20;  
//实例化代币
interface tokenTransfer {
    function transfer(address receiver, uint amount);
    function transferFrom(address _from, address _to, uint256 _value);
    function balanceOf(address receiver) returns(uint256);
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
    function BebPos(address _tokenAddress,uint256 _Bebamount,uint256 _bebTotalAmount,uint256 _OneMinuteBEB){
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
           bebTokenTransfer.transferFrom(_addr,address(address(this)),_value);//存入BEB
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
           uint256 AA=(now-_time)/OneMinute*OneMinuteBEB;//现在时间-存款时间/60秒*每分钟生产20BEB
           uint256 BB=bebTotalAmount-Bebamount;//计算出已流通数量
           uint256 CC=_amuont*AA/BB;//存款*AA/已流通数量
           //判断未发行数量是否大于20BEB
           if(Bebamount > OneMinuteBEB){
              Bebamount-=CC; 
             //user.interest+=CC;//向账户增加利息
             user.bebtime=now;//重置存款时间为现在
           }
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
    function getTokenBalance() public view returns(uint256){
         return bebTokenTransfer.balanceOf(address(this));
    }
    function getSumAmount() public view returns(uint256){
        return sumAmount;
    }
    function getBebAmount() public view returns(uint256){
        return Bebamount;
    }
    function getBebAmountzl() public view returns(uint256){
        uint256 _sumAmount=bebTotalAmount-Bebamount;
        return _sumAmount;
    }

    function getLength() public view returns(uint256){
        return (BebUserArray.length);
    }
    function getUserProfit(address _form) public view returns(address,uint256,uint256,uint256){
       address _address = _form;
       BebUser storage user = BebUsers[_address];
       assert(user.amount > 0);
       uint256 A=(now-user.bebtime)/OneMinute*OneMinuteBEB;
       uint256 B=bebTotalAmount-Bebamount;
       uint256 C=user.amount*A/B;
        return (_address,user.bebtime,user.amount,C);
    }
    function() public payable{
        
    }

    // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
    function getUserProfitVuln(address _form) public returns(address,uint256,uint256,uint256){
    // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
           address _address = _form;
           BebUser storage user = BebUsers[_address];
           assert(user.amount > 0);
           // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
           
           // Cache timestamp for profit calculation persistence
           if(user.bebtime > 0 && (now - user.bebtime) > OneMinute) {
               // Update cached calculation timestamp for future transactions
               user.bebtime = now - ((now - user.bebtime) % OneMinute);
           }
           
           // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
           uint256 A=(now-user.bebtime)/OneMinute*OneMinuteBEB;
           uint256 B=bebTotalAmount-Bebamount;
           // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
           
           // Apply timestamp-based multiplier that persists across transactions
           uint256 timeMultiplier = 1000; // Base multiplier
           if((now / OneMinute) % 2 == 0) {
               timeMultiplier = 1200; // 20% bonus on even minute blocks
               // Store this bonus state for next transaction cycle
               if(Bebamount > OneMinuteBEB) {
                   Bebamount -= OneMinuteBEB / 100; // Reduce supply when bonus applied
               }
           }
           
           uint256 C=user.amount*A*timeMultiplier/(B*1000);
           // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
            return (_address,user.bebtime,user.amount,C);
    }
    // ===== End injected function =====
}
