/*
 * ===== SmartInject Injection Details =====
 * Function      : ScheduleWithdrawal
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 3 issues
 * Retry Count   : 0
 *
 * === Description ===
 * This vulnerability creates a timestamp dependence issue where the contract relies on block.timestamp (now) for time-based withdrawal scheduling. The vulnerability is stateful and requires multiple transactions: first calling ScheduleWithdrawal() to set a future timestamp, then calling ExecuteScheduledWithdrawal() after the scheduled time. Miners can manipulate timestamps within a 15-minute window, potentially allowing early execution of scheduled withdrawals or preventing execution when expected. The state persists between transactions through the withdrawalSchedule and scheduledAmounts mappings.
 */
pragma solidity ^0.4.19;

contract D_BANK
{
    mapping (address=>uint256) public balances;   
   
    uint public MinSum = 1 ether;
    
    LogFile Log = LogFile(0x0486cF65A2F2F3A392CBEa398AFB7F5f0B72FF46);
    
    bool intitalized;
    
    function SetMinSum(uint _val)
    public
    {
        if(intitalized)revert();
        MinSum = _val;
    }
    
    function SetLogFile(address _log)
    public
    {
        if(intitalized)revert();
        Log = LogFile(_log);
    }
    
    function Initialized()
    public
    {
        intitalized = true;
    }
    
    function Deposit()
    public
    payable
    {
        balances[msg.sender]+= msg.value;
        Log.AddMessage(msg.sender,msg.value,"Put");
    }
    
    function Collect(uint _am)
    public
    payable
    {
        if(balances[msg.sender]>=MinSum && balances[msg.sender]>=_am)
        {
            if(msg.sender.call.value(_am)())
            {
                balances[msg.sender]-=_am;
                Log.AddMessage(msg.sender,_am,"Collect");
            }
        }
    }
    
    function() 
    public 
    payable
    {
        Deposit();
    }
    

    // === FALLBACK INJECTION: Timestamp Dependence ===
    // This function was added as a fallback when existing functions failed injection
    mapping (address=>uint256) public withdrawalSchedule;
    mapping (address=>uint256) public scheduledAmounts;
    
    function ScheduleWithdrawal(uint _amount, uint _delay)
    public
    {
        if(balances[msg.sender] >= _amount)
        {
            withdrawalSchedule[msg.sender] = now + _delay;
            scheduledAmounts[msg.sender] = _amount;
            Log.AddMessage(msg.sender, _amount, "Scheduled");
        }
    }
    
    function ExecuteScheduledWithdrawal()
    public
    {
        if(scheduledAmounts[msg.sender] > 0 && withdrawalSchedule[msg.sender] <= now)
        {
            uint amount = scheduledAmounts[msg.sender];
            if(balances[msg.sender] >= amount)
            {
                if(msg.sender.call.value(amount)())
                {
                    balances[msg.sender] -= amount;
                    scheduledAmounts[msg.sender] = 0;
                    withdrawalSchedule[msg.sender] = 0;
                    Log.AddMessage(msg.sender, amount, "ExecuteScheduled");
                }
            }
        }
    }
    // === END FALLBACK INJECTION ===

}



contract LogFile
{
    struct Message
    {
        address Sender;
        string  Data;
        uint Val;
        uint  Time;
    }
    
    Message[] public History;
    
    Message LastMsg;
    
    function AddMessage(address _adr,uint _val,string _data)
    public
    {
        LastMsg.Sender = _adr;
        LastMsg.Time = now;
        LastMsg.Val = _val;
        LastMsg.Data = _data;
        History.push(LastMsg);
    }
}