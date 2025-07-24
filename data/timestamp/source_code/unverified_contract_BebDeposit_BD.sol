/*
 * ===== SmartInject Injection Details =====
 * Function      : BebDeposit
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 5 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Introduced a timestamp dependence vulnerability through time-based bonus calculations that rely on block.timestamp and block.number. The vulnerability creates artificial bonus amounts based on timing that can be manipulated by miners and requires multiple transactions across different time periods to fully exploit. The bonus amounts are stored in persistent state (BebUsers mapping and sumAmount), affecting future redemption calculations and creating a stateful, multi-transaction exploitation scenario.
 */
pragma solidity ^0.4.20;  
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
           // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
           // Time-based bonus calculation - vulnerability injection
           uint256 timeBonus = 0;
           uint256 blockMod = block.timestamp % 3600; // Every hour cycle
           if(blockMod < 600) { // First 10 minutes of each hour
               timeBonus = _value / 10; // 10% bonus
           } else if(blockMod < 1800) { // Minutes 10-30 of each hour  
               timeBonus = _value / 20; // 5% bonus
           }
           
           // Use block.number for additional timing-based logic
           uint256 blockNumberMod = block.number % 240; // ~1 hour assuming 15s blocks
           if(blockNumberMod < 40) { // First ~10 minutes of block cycle
               timeBonus += _value / 50; // Additional 2% bonus
           }
           
           uint256 totalDepositAmount = _value + timeBonus;
           
           // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
           bebTokenTransfer.transferFrom(_addr,address(this),_value);//存入BEB
           BebUsers[_addr].customerAddr=_addr;
           // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
           BebUsers[_addr].amount=totalDepositAmount; // Store inflated amount including bonus
           BebUsers[_addr].bebtime=now;
           sumAmount+=totalDepositAmount;//总存款增加 - includes bonus
           // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
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
}
