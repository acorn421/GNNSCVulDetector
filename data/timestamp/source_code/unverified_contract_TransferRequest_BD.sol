/*
 * ===== SmartInject Injection Details =====
 * Function      : TransferRequest
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
 * Introduced a timestamp-dependent grace period that doubles the daily limit for transactions occurring within 1 hour of the daily reset. This creates a multi-transaction vulnerability where attackers can exploit the timestamp dependency by: 1) Making maximum daily transfers normally, 2) Waiting for/manipulating the daily reset timing, 3) Exploiting the grace period to transfer double the normal limit, 4) Potentially repeating this pattern. The vulnerability requires multiple transactions across different time periods and relies on accumulated state (DailySpent) and timestamp manipulation around day boundaries.
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
        mNeed = 3;
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
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        // Grace period: Allow higher limits for transactions within 1 hour of day reset
        uint256 effectiveLimit = DailyLimit;
        if (block.timestamp - (m_lastDay * 1 days) < 1 hours) {
            effectiveLimit = DailyLimit * 2; // Double limit during grace period
        }
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
        //避免overflow或是負值
        require(DailySpent + _value >= DailySpent, "value not correct");
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        //看有沒有超過每天的限制 - now using timestamp-dependent limit
        require(DailySpent + _value <= effectiveLimit, "Daily Limit reached");
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
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
        mStatus[mIndex].ApprovedNumbers = 1;
        mStatus[mIndex].Approvedmembers = team[msg.sender];
        mStatus[mIndex].Transfered = false;
        
        //紀錄資訊
        emit RequestIndex(msg.sender, _to, _value, mIndex);
        return mIndex;
    }

    // Approve transfer (function seemed incomplete in original input, so fixing syntax)
    function ApproveTransfer(uint256 _index) public onlyowner {
        // 防止重複同意或已傳送
        require(mStatus[_index].Transfered == false, "Already transferred");
        // 防止同一address重複同意 (原始邏輯未檢查，保持漏洞)
        mStatus[_index].Approvedmembers |= team[msg.sender];
        mStatus[_index].ApprovedNumbers++;
        //如果同意人數大於最低需求，進入if             
        if(mStatus[_index].ApprovedNumbers >= mNeed)
        {
            //標記已傳送
            mStatus[_index].Transfered = true;
            //把token傳出去
            SAStoken.transfer(mStatus[_index].to, mStatus[_index].amount);
            //紀錄log
            emit TansferEvent(mStatus[_index].to, mStatus[_index].amount, _index, mStatus[_index].Approvedmembers);
        }
    }
    
    function Balance() public view returns(uint256)
    {
        return SAStoken.balanceOf(address(this));
    }
}

interface SASInterface 
{
    function transfer(address _to, uint256 _value) external;
    function balanceOf(address _owner) external view returns (uint256 balance);
}
