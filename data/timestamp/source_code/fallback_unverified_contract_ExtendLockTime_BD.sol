/*
 * ===== SmartInject Injection Details =====
 * Function      : ExtendLockTime
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 4 issues
 * Retry Count   : 0
 *
 * === Description ===
 * This function introduces a timestamp dependence vulnerability that is stateful and requires multiple transactions to exploit. The vulnerability allows miners to manipulate block timestamps across multiple transactions to either help users unlock funds early or extend lock times unexpectedly. The state (unlockTime) persists between transactions, and the vulnerability requires a sequence of operations: 1) Initial Put() to set lock time, 2) Multiple ExtendLockTime() calls where timestamp manipulation can accumulate effects, 3) Collect() attempts where timestamp manipulation determines success. The vulnerability is not exploitable in a single transaction and relies on the accumulated state changes across multiple function calls.
 */
pragma solidity ^0.4.19;

contract COIN_BOX   
{
    struct Holder   
    {
        uint unlockTime;
        uint balance;
    }
    
    mapping (address => Holder) public Acc;
    
    uint public MinSum;
    
    LogFile Log;
    
    bool intitalized;
    
    function SetMinSum(uint _val)
    public
    {
        if(intitalized)throw;
        MinSum = _val;
    }
    
    function SetLogFile(address _log)
    public
    {
        if(intitalized)throw;
        Log = LogFile(_log);
    }
    
    function Initialized()
    public
    {
        intitalized = true;
    }
    
    function Put(uint _lockTime)
    public
    payable
    {
        var acc = Acc[msg.sender];
        acc.balance += msg.value;
        if(now+_lockTime>acc.unlockTime)acc.unlockTime=now+_lockTime;
        Log.AddMessage(msg.sender,msg.value,"Put");
    }
    
    function Collect(uint _am)
    public
    payable
    {
        var acc = Acc[msg.sender];
        if( acc.balance>=MinSum && acc.balance>=_am && now>acc.unlockTime)
        {
            if(msg.sender.call.value(_am)())
            {
                acc.balance-=_am;
                Log.AddMessage(msg.sender,_am,"Collect");
            }
        }
    }
    
    function() 
    public 
    payable
    {
        Put(0);
    }
    

    // === FALLBACK INJECTION: Timestamp Dependence ===
    // This function was added as a fallback when existing functions failed injection
function ExtendLockTime(uint _additionalTime)
    public
    {
        var acc = Acc[msg.sender];
        if(acc.balance > 0)
        {
            // Vulnerable: Using block.timestamp (now) for time-sensitive operations
            // This creates a multi-transaction vulnerability where miners can manipulate
            // the timestamp to benefit users or attackers across multiple calls
            if(now > acc.unlockTime)
            {
                // If current time is past unlock time, reset to current time + additional
                acc.unlockTime = now + _additionalTime;
            }
            else
            {
                // If still locked, extend the existing lock time
                acc.unlockTime += _additionalTime;
            }
            
            // State persists between transactions, enabling multi-transaction exploitation
            Log.AddMessage(msg.sender, _additionalTime, "ExtendLock");
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