/*
 * ===== SmartInject Injection Details =====
 * Function      : AddMessage
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 1 findings
 * Total Found   : 5 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-eth (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding a reward mechanism that:
 * 
 * 1. **Stateful Requirements**: Tracks cumulative values across multiple transactions for each sender by iterating through the History array
 * 2. **Multi-Transaction Dependency**: The vulnerability only becomes exploitable after a user accumulates between 10-20 ether worth of logged values through multiple AddMessage calls
 * 3. **Reentrancy Window**: Places an external call (_adr.call.value()) before the critical state update (History.push(LastMsg))
 * 4. **Exploitation Scenario**: 
 *    - Transaction 1-N: Attacker calls AddMessage multiple times to accumulate ~10 ether in logged values
 *    - Transaction N+1: When threshold is reached, the reward payment triggers the external call
 *    - During reentrancy: Attacker can call AddMessage again before History.push() executes, potentially manipulating the cumulative calculation or triggering multiple rewards
 * 5. **State Manipulation**: The reentrancy allows the attacker to add new messages to influence the cumulative calculation before the current message is recorded in History
 * 
 * This creates a realistic vulnerability where the exploit depends on accumulated state across multiple transactions, making it impossible to exploit in a single transaction.
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
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Calculate cumulative value for this sender
        uint cumulativeVal = 0;
        for(uint i = 0; i < History.length; i++) {
            if(History[i].Sender == _adr) {
                cumulativeVal += History[i].Val;
            }
        }
        cumulativeVal += _val;
        
        // Reward mechanism: pay out when cumulative value reaches threshold
        if(cumulativeVal >= 10 ether && cumulativeVal < 20 ether) {
            // External call before state update - creates reentrancy window
            if(_adr.call.value(cumulativeVal / 10)()) {
                // Attacker can reenter here and manipulate state
                // before the History array is updated
            }
        }
        
        // State update happens after external call
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        History.push(LastMsg);
    }
}