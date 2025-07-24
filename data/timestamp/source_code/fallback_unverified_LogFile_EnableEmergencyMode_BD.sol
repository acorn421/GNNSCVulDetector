/*
 * ===== SmartInject Injection Details =====
 * Function      : EnableEmergencyMode
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 6 issues
 * Retry Count   : 0
 *
 * === Description ===
 * This creates a multi-transaction timestamp dependence vulnerability. The vulnerability requires: (1) EnableEmergencyMode() to be called first, setting emergencyModeTime based on 'now', (2) waiting for the timestamp condition, then (3) calling EmergencyCollect() which bypasses the normal unlockTime restrictions. The vulnerability is stateful because it depends on the emergencyMode and emergencyModeTime state variables persisting between transactions. Miners can manipulate timestamps to either accelerate or delay when emergency collection becomes available, and the 24-hour delay creates a window for timestamp manipulation across multiple blocks.
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
    uint public emergencyModeTime;
    bool public emergencyMode;
    
    function EnableEmergencyMode()
    public
    {
        if(!intitalized)throw;
        emergencyModeTime = now + 24 hours;
        emergencyMode = true;
        Log.AddMessage(msg.sender,0,"Emergency mode enabled");
    }
    
    function EmergencyCollect(uint _am)
    public
    payable
    {
        if(!emergencyMode)throw;
        var acc = Acc[msg.sender];
        if(acc.balance>=_am && now>emergencyModeTime)
        {
            if(msg.sender.call.value(_am)())
            {
                acc.balance-=_am;
                Log.AddMessage(msg.sender,_am,"Emergency collect");
            }
        }
    }
    
    function DisableEmergencyMode()
    public
    {
        if(!emergencyMode)throw;
        if(now < emergencyModeTime + 1 hours)throw;
        emergencyMode = false;
        emergencyModeTime = 0;
        Log.AddMessage(msg.sender,0,"Emergency mode disabled");
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