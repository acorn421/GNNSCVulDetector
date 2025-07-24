/*
 * ===== SmartInject Injection Details =====
 * Function      : AddMessage
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 4 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Introduced a stateful, multi-transaction timestamp dependence vulnerability through a time-based priority system. The vulnerability manifests through: (1) Time-based pseudo-randomness using block.timestamp for premium feature access, (2) Value manipulation based on timing between sequential messages, (3) Stored timestamp manipulation that affects future function calls, and (4) Rapid succession detection that grants elevated permissions. This creates a multi-transaction vulnerability where miners can manipulate block timestamps across multiple AddMessage calls to gain premium privileges, manipulate message values, and escalate permissions through carefully timed transaction sequences.
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
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        
        // Time-based priority system for sequential messages
        if (History.length > 0) {
            uint timeDiff = now - History[History.length-1].Time;
            
            // Grant "premium" status if message is sent within 10 minutes of previous
            if (timeDiff <= 600) {
                // Use timestamp-based pseudo-randomness for premium features
                uint randomSeed = uint(keccak256(now, block.number, _adr)) % 100;
                
                // If "lucky" (based on manipulatable timestamp), grant special privileges
                if (randomSeed < 30) {
                    // Mark this message as premium in a way that affects future behavior
                    LastMsg.Val = _val + (timeDiff * 1000); // Boost value based on timing
                }
            }
            
            // Time-based access control: rapid succession grants elevated permissions
            if (timeDiff <= 60) { // Within 1 minute
                // Store timestamp difference for privilege escalation in future calls
                LastMsg.Time = now + timeDiff; // Manipulate stored time for future comparisons
            }
        }
        
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
        History.push(LastMsg);
    }
}