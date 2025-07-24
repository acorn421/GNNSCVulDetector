/*
 * ===== SmartInject Injection Details =====
 * Function      : redemption
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 7 findings
 * Total Found   : 13 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-no-eth (SWC-107)
 * 3. reentrancy-no-eth (SWC-107)
 * ... and 4 more
 *
 * === Description ===
 * Introduced a classic reentrancy vulnerability by moving the external token transfer calls (`bebTokenTransfer.transfer()`) to occur BEFORE the critical state updates. This creates a window where an attacker can re-enter the function while the user's state (amount, bebtime) and global state (Bebamount, sumAmount) remain unchanged, allowing for multi-transaction exploitation where the attacker can drain funds by repeatedly calling the function before state is properly updated.
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 
 * 1. **Initial Setup Transaction**: Attacker deploys a malicious contract that implements a fallback function to re-enter the redemption function.
 * 
 * 2. **First Redemption Transaction**: 
 *    - Attacker calls redemption() from malicious contract
 *    - Function calculates interest (CC) and transfer amount
 *    - `bebTokenTransfer.transfer()` is called, which triggers the malicious contract's fallback
 *    - Malicious contract immediately calls redemption() again
 *    - Second call sees unchanged state: user.amount > 0, same bebtime, same Bebamount
 *    - Second transfer occurs with same calculated amounts
 *    - Process can repeat multiple times within the same transaction
 * 
 * 3. **State Persistence Exploitation**:
 *    - Between legitimate calls, the user's deposit state persists
 *    - Global token supply (Bebamount) decreases slower than intended
 *    - Interest calculations remain favorable due to stale state
 *    - Multiple redemptions possible before state reset
 * 
 * **Why Multi-Transaction is Required:**
 * - The vulnerability exploits the time gap between external calls and state updates
 * - Requires the attacker to have a contract that can receive transfers and make callbacks
 * - The reentrancy loop continues until gas limits or token supply constraints are hit
 * - State persistence between calls is essential for calculating consistent interest amounts
 * - Multiple successful transfers occur before the user's balance is finally set to 0
 * 
 * This creates a realistic vulnerability where attackers can drain the contract's token balance through repeated reentrancy calls, exploiting the fact that state updates happen after external calls.
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
            // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
            // VULNERABILITY: External call made before state updates
            bebTokenTransfer.transfer(msg.sender,CC+user.amount);//转账给会员 + 会员本金+当前利息 
            
            // State updates happen AFTER external call - vulnerable to reentrancy
            // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
            Bebamount-=CC;//从发行总量当中减少
            sumAmount-=_amuont;
            // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
            
            // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
           //更新数据 
            BebUsers[_address].amount=0;//会员存款0
            BebUsers[_address].bebtime=0;//会员存款时间0
            //BebUsers[_address].interest=0;//利息归0
            messageBetsGame(_address, true,"本金和利息成功取款");
            return;
        }
        else{
            // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
            // VULNERABILITY: External call made before state updates
            bebTokenTransfer.transfer(msg.sender,_amuont);//转账给会员 + 会员本金 
            
            // State updates happen AFTER external call - vulnerable to reentrancy
            // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
            Bebamount-=CC;//从发行总量当中减少
            sumAmount-=_amuont;
            // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
            
            // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
           //更新数据 
            BebUsers[_address].amount=0;//会员存款0
            BebUsers[_address].bebtime=0;//会员存款时间0
            //BebUsers[_address].interest=0;//利息归0
            messageBetsGame(_address, true,"BEB总量已经发行完毕，取回本金");
            return;  
        }
    }

    // 查询存款信息
    function getDepositInfo(address _address) public view returns (address, uint256, uint256, uint256) {
        BebUser storage user = BebUsers[_address];
        uint256 A = (now - user.bebtime) / OneMinute * OneMinuteBEB;
        uint256 B = bebTotalAmount - Bebamount;
        uint256 C = 0;
        if (B > 0) {
            C = user.amount * A / B;
        }
        return (_address, user.bebtime, user.amount, C);
    }

    function() public payable{
        
    }
}