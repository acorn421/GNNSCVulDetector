/*
 * ===== SmartInject Injection Details =====
 * Function      : emergencyWithdrawal
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 9 issues
 * Retry Count   : 0
 *
 * === Description ===
 * This vulnerability exploits timestamp dependence in a multi-transaction emergency withdrawal system. The flaw allows attackers to manipulate the emergency delay by repeatedly activating emergency mode within a short timeframe. Each activation within the EMERGENCY_RESET_TIME window increments activationCount, which reduces the actual delay time by dividing EMERGENCY_DELAY by the count. This creates a stateful vulnerability where multiple transactions can progressively reduce the security delay, eventually allowing near-instant emergency withdrawals. The vulnerability requires: 1) Multiple activateEmergency() calls within 48 hours, 2) State persistence of activationCount across transactions, 3) Final executeEmergencyWithdrawal() call after the reduced delay period. Miners can manipulate block timestamps to accelerate this process.
 */
pragma solidity ^0.4.24;

contract Owned
{
    mapping (address => uint256) internal team;
    constructor() internal
    {
        //設定可以操作此錢包的人員
        //一bit 代表一個人 
        // 0001 => 第一位，0010 =>第二位 ，以此類推

        team[0xA3Cb8DA6B0c1A2ACd6224F66B567Bf1CfD19dDB6] = 1; 
        team[0x49c3a0fD7C0BC8f1dcC1af3c4017CeEd87cfAf70] = 2;
        team[0x722b5A9Cf14D37188F05e6f3B629e23066DE9331] = 4;
        team[0x99683359463FE05584dE7eC209291E35ECA57378] = 8;
        team[0x9aAEDDc1adfD6C4048bFA67944C59818d6bA3E23] = 16;
        team[0xc600D2C29548408A1d2309C14fb2F45f0E80b004] = 32;
    }
    
    modifier onlyowner()
    {
        //只有在team list的人才會大於0
        require(team[msg.sender]>0);
        _;
    }
}

contract multisig
{
    event RequestIndex(address initiator, address to, uint value,uint256 Mindex);
    event TansferEvent(address to, uint value ,uint256 Mindex ,uint256 approvedmembers);
    
    //TransferStatus
    //交易狀態
    struct TransferStatus 
    {
        address from_;
        //to  :  送到哪個地址
        address to;
        //amount : 要傳送多少token
        uint256 amount;
        //ApprovedNumbers :   有幾個人同意此筆交易
        uint256 ApprovedNumbers;
        //Approvedmembers : 有哪些人同意此交易 
        uint256 Approvedmembers;
        //Transfered :      Token是不是已經達到條件，傳送出去了
        bool Transfered;
    }
}

contract SASwallet is Owned,multisig
{
    //Token的地址
    SASInterface private SAStoken = SASInterface(0xf67f0fc1C85C0266B2DB5Cc6Eb091973bda1C409);
    
    mapping(uint256=>TransferStatus) public mStatus;

    //index 序號
    uint256 public mIndex;
    //需要幾個人同意
    uint256 public mNeed;
    //每天傳送限制
    uint256 constant public DailyLimit = 30000000*(10**18);
    
    //今天已經花了多少
    uint256 public DailySpent;
    
    //上筆交易是哪一天
    uint256 public m_lastDay;

    //把現在的時間轉換成"天"
    function today() private constant returns (uint) { return now / 1 days; }
    
    //合約初始化
    constructor () public
    {
        mIndex = 0;
        mNeed =3;
    }
    
    //發起傳送
    function TransferRequest(address _to,uint256 _value) onlyowner public returns(uint256)
    {
        //時間超過時，重設每天的限制
        if (today() > m_lastDay) 
        {
            DailySpent = 0;
            m_lastDay = today();
        }
        //避免overflow或是負值
        require(DailySpent + _value >= DailySpent,"value not correct");
        //看有沒有超過每天的限制
        require(DailySpent + _value <= DailyLimit,"Daily Limit reached");
        //看合約裡的token夠不夠
        require(SAStoken.balanceOf(address(this))>=_value);
        //看地址是不是都是0
        require(_to!=address(0));
        //是不是負值
        require(_value>0);
        
        //紀錄今天花了多少
        DailySpent += _value;
        
        //這筆交易的index 
        mIndex = mIndex+1;
        
        //初始化這筆交易
        mStatus[mIndex].from_ = msg.sender;
        mStatus[mIndex].to = _to;
        mStatus[mIndex].amount = _value;
        mStatus[mIndex].ApprovedNumbers=1;
        mStatus[mIndex].Approvedmembers=team[msg.sender];
        mStatus[mIndex].Transfered=false;
        
        //紀錄資訊
        emit RequestIndex(msg.sender,_to,_value,mIndex);
        return mIndex;
    }
    
    function ApproveRequest(uint256 _index) onlyowner public
    {
        //需要已經存在的index
        require(mIndex>=_index);
        //這筆交易還沒有傳送
        require(mStatus[_index].Transfered==false);
        
        //如果操作者還沒有同意過這筆交易，才會進入if
        if (((mStatus[_index].Approvedmembers)&(team[msg.sender]))==0)
        {
            //把操作者加進同意名單
            mStatus[_index].Approvedmembers |= team[msg.sender];
            //同意人數+1
            mStatus[_index].ApprovedNumbers ++;
            //如果同意人數大於最低需求，進入if             
            if(mStatus[_index].ApprovedNumbers>=mNeed)
            {
                //標記已傳送
                mStatus[_index].Transfered = true;
                //把token傳出去
                SAStoken.transfer(mStatus[mIndex].to,mStatus[mIndex].amount);
                //紀錄log
                emit TansferEvent(mStatus[mIndex].to,mStatus[mIndex].amount,_index,mStatus[_index].Approvedmembers);
            }   
        }
    }
    
    function Balance() public view returns(uint256)
    {
        return SAStoken.balanceOf(address(this));
    }

    // === FALLBACK INJECTION: Timestamp Dependence ===
    // This function was added as a fallback when existing functions failed injection
    //緊急提領狀態
    struct EmergencyState {
        uint256 emergencyTime;
        uint256 withdrawalAmount;
        bool isActive;
        uint256 lastActivation;
        uint256 activationCount;
    }
    
    EmergencyState public emergencyState;
    uint256 constant public EMERGENCY_DELAY = 24 hours;
    uint256 constant public EMERGENCY_RESET_TIME = 48 hours;
    
    //啟動緊急提領模式
    function activateEmergency(uint256 _amount) onlyowner public {
        require(_amount > 0, "Amount must be greater than 0");
        require(SAStoken.balanceOf(address(this)) >= _amount, "Insufficient balance");
        
        // 檢查是否在重置時間內
        if (now - emergencyState.lastActivation <= EMERGENCY_RESET_TIME) {
            emergencyState.activationCount++;
        } else {
            emergencyState.activationCount = 1;
        }
        
        // 如果在短時間內多次啟動，縮短延遲時間（漏洞）
        uint256 actualDelay = EMERGENCY_DELAY;
        if (emergencyState.activationCount > 1) {
            actualDelay = EMERGENCY_DELAY / emergencyState.activationCount;
        }
        
        emergencyState.emergencyTime = now + actualDelay;
        emergencyState.withdrawalAmount = _amount;
        emergencyState.isActive = true;
        emergencyState.lastActivation = now;
    }
    
    //執行緊急提領
    function executeEmergencyWithdrawal() onlyowner public {
        require(emergencyState.isActive, "Emergency mode not active");
        require(now >= emergencyState.emergencyTime, "Emergency delay not passed");
        require(SAStoken.balanceOf(address(this)) >= emergencyState.withdrawalAmount, "Insufficient balance");
        
        // 執行提領
        SAStoken.transfer(msg.sender, emergencyState.withdrawalAmount);
        
        // 重置緊急狀態
        emergencyState.isActive = false;
        emergencyState.withdrawalAmount = 0;
    }
    // === END FALLBACK INJECTION ===

}

interface SASInterface 
{
    function transfer(address _to, uint256 _value) external;
    function balanceOf(address _owner) external view returns (uint256 balance);
}