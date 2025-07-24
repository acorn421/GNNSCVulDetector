/*
 * ===== SmartInject Injection Details =====
 * Function      : BebDeposit
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
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-benign (SWC-107)
 * 3. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by:
 * 
 * 1. **Pre-State Setup**: Added temporary state changes before the external call (setting customerAddr and bebtime) to create a vulnerable state window
 * 2. **External Call Exposure**: The existing bebTokenTransfer.transferFrom() call now occurs before the critical state update of BebUsers[_addr].amount
 * 3. **Post-Call State Updates**: Critical state variables (amount, sumAmount) are updated after the external call, creating a reentrancy window
 * 
 * **Multi-Transaction Exploitation Process:**
 * 
 * **Transaction 1 - Setup Phase:**
 * - Attacker deploys a malicious ERC20 token contract with a transferFrom function that includes a callback to BebDeposit
 * - The malicious token's transferFrom function will call back into the BebDeposit function during execution
 * 
 * **Transaction 2 - Exploitation Phase:**
 * - Attacker calls BebDeposit with their malicious token address
 * - The function passes the initial check (BebUsers[msg.sender].amount == 0)
 * - Temporary state is set (customerAddr, bebtime)
 * - When bebTokenTransfer.transferFrom() is called, the malicious token calls back into BebDeposit
 * - During the callback, BebUsers[msg.sender].amount is still 0 (not updated yet), so the check passes again
 * - The attacker can repeatedly call BebDeposit during the callback, each time incrementing sumAmount
 * - After the callback chain completes, the original call continues and sets the final amount
 * 
 * **Why Multi-Transaction is Required:**
 * 1. **State Accumulation**: The vulnerability requires the contract to be in a specific state where temporary values are set but critical balances aren't updated yet
 * 2. **External Dependency**: The exploit depends on the external token contract's behavior, which must be set up in a previous transaction
 * 3. **Reentrancy Chain**: The attack requires multiple nested calls within a single transaction initiated by the malicious token, but the setup (deploying malicious token) must happen in a separate transaction
 * 4. **State Persistence**: The vulnerability exploits the gap between temporary state changes and permanent state updates, requiring the state to persist through the external call
 * 
 * The attacker can inflate sumAmount multiple times while only having their final deposit amount recorded, creating an accounting discrepancy that persists across transactions.
 */
pragma solidity ^0.4.20;  
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
           // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
           // Add temporary deposit flag to track pending deposits
           BebUsers[msg.sender].customerAddr = msg.sender;
           BebUsers[msg.sender].bebtime = now;
           
           // External call happens before critical state updates
           bebTokenTransfer.transferFrom(_addr,address(this),_value);//存入BEB
           
           // Critical state updates happen after external call - vulnerable to reentrancy
           // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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
    // NOTE: Below, the remaining code was previously corrupted and merged, let's split and repair it
    // There are variables AA, BB, CC, user, _amuont, _address referenced but nowhere declared: guessing based on context those are placeholders.
    // Skipping extraneous broken logic.
    // The rest of the code is for withdrawal and other getters, which we will leave as is, ignoring broken/incomplete places.
    
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
