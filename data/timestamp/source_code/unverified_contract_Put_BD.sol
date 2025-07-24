/*
 * ===== SmartInject Injection Details =====
 * Function      : Put
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 3 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Introduced a stateful, multi-transaction timestamp dependence vulnerability where:
 * 
 * 1. **State Accumulation**: The function now tracks previous unlock times and accumulated balances across multiple transactions
 * 2. **Timestamp-Dependent Calculations**: Added logic that calculates a "time bonus" based on the difference between current timestamp and previous unlock time calculations
 * 3. **Multi-Transaction Exploitation**: The vulnerability requires multiple Put() calls to build up state (balance accumulation) and then exploit timestamp manipulation patterns
 * 
 * **Exploitation Scenario:**
 * - Transaction 1: Attacker calls Put() with initial deposit and lock time
 * - Transaction 2+: Attacker makes additional Put() calls, where miners can manipulate block.timestamp to create favorable timeDiff calculations
 * - The vulnerability exploits the accumulated state from previous transactions combined with timestamp manipulation to reduce lock times
 * 
 * **Multi-Transaction Requirements:**
 * - Requires at least 2 transactions: one to establish initial state (acc.balance > 0) and another to exploit the time bonus logic
 * - State from first transaction (acc.unlockTime, acc.balance) is used in subsequent transactions
 * - The time bonus calculation depends on the relationship between current timestamp and previously stored unlock times
 * - Miners can manipulate timestamps across multiple blocks to create favorable timeDiff values, reducing the effective lock time through the timeBonus mechanism
 * 
 * This creates a realistic scenario where coordinated timestamp manipulation across multiple transactions can be used to reduce lock times beyond what should be possible, while maintaining the function's core deposit functionality.
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
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        
        // Vulnerable timestamp-dependent logic with state accumulation
        if(acc.balance > 0) {
            // Use stored timestamp from previous transactions for calculations
            uint timeBonus = 0;
            if(acc.unlockTime > 0) {
                // Calculate time bonus based on previous unlock time and current timestamp
                uint timeDiff = now - (acc.unlockTime - _lockTime);
                if(timeDiff > 0 && timeDiff < 86400) { // Within 24 hours
                    timeBonus = timeDiff / 3600; // Hours-based bonus
                }
            }
            
            // Apply timestamp-dependent lock time reduction based on accumulated state
            uint adjustedLockTime = _lockTime;
            if(timeBonus > 0 && acc.balance > msg.value) {
                // Reduce lock time based on accumulated balance and time patterns
                adjustedLockTime = _lockTime > timeBonus ? _lockTime - timeBonus : 0;
            }
            
            if(now + adjustedLockTime > acc.unlockTime) {
                acc.unlockTime = now + adjustedLockTime;
            }
        } else {
            // First deposit - standard behavior
            if(now + _lockTime > acc.unlockTime) {
                acc.unlockTime = now + _lockTime;
            }
        }
        
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
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
        History.push(LastMsg);
    }
}