/*
 * ===== SmartInject Injection Details =====
 * Function      : emergencyWithdraw
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 6 findings
 * Total Found   : 15 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-no-eth (SWC-107)
 * 3. reentrancy-no-eth (SWC-107)
 * ... and 3 more
 *
 * === Description ===
 * This function introduces a stateful, multi-transaction reentrancy vulnerability. The vulnerability requires: 1) Owner to first call enableEmergencyMode() to set emergencyMode=true, 2) User to call emergencyWithdraw() which has a reentrancy vulnerability due to external token transfer before state updates, 3) The emergencyWithdrawals mapping tracks withdrawal status but is updated after the external call, allowing reentrancy attacks where malicious contracts can call back into emergencyWithdraw() before the state is properly updated.
 */
pragma solidity^0.4.20;  
//实例化代币
interface tokenTransfer {
    function transfer(address receiver, uint amount) external;
    function transferFrom(address _from, address _to, uint256 _value) external;
    function balanceOf(address receiver) external view returns(uint256);
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
    // === FALLBACK INJECTION: Reentrancy ===
    // This function was added as a fallback when existing functions failed injection
// Emergency withdrawal function with reentrancy vulnerability
    bool public emergencyMode = false;
    mapping(address => bool) public emergencyWithdrawals;
    
    // Function to enable emergency mode (only owner)
    function enableEmergencyMode() public onlyOwner {
        emergencyMode = true;
        messageBetsGame(msg.sender, true, "Emergency mode enabled");
    }
    
    // Function to disable emergency mode (only owner)
    function disableEmergencyMode() public onlyOwner {
        emergencyMode = false;
        messageBetsGame(msg.sender, true, "Emergency mode disabled");
    }
    
    // Emergency withdrawal function - vulnerable to reentrancy
    function emergencyWithdraw() public {
        require(emergencyMode, "Emergency mode not active");
        
        address _address = msg.sender;
        BebUser storage user = BebUsers[_address];
        require(user.amount > 0, "No funds to withdraw");
        require(!emergencyWithdrawals[_address], "Already withdrawn in emergency mode");
        
        // Calculate partial withdrawal amount (50% of deposit)
        uint256 withdrawAmount = user.amount / 2;
        
        // Mark as withdrawn AFTER external call - vulnerable to reentrancy
        if (withdrawAmount > 0) {
            // External call before state update - VULNERABLE
            bebTokenTransfer.transfer(msg.sender, withdrawAmount);
            
            // State update after external call - allows reentrancy
            emergencyWithdrawals[_address] = true;
            user.amount -= withdrawAmount;
            sumAmount -= withdrawAmount;
            
            messageBetsGame(_address, true, "Emergency withdrawal completed");
        }
    }
    // === END FALLBACK INJECTION ===

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
}