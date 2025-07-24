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
 * Total Found   : 2 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Introduced a stateful, multi-transaction timestamp dependence vulnerability through time-based access controls and rate limiting. The vulnerability manifests in two ways:
 * 
 * 1. **Rate Limiting Bypass**: The function uses `now - LastMsg.Time < 300` to implement a 5-minute cooldown between messages. Since miners can manipulate block timestamps within a 15-second window, an attacker can bypass this cooldown by having a miner set favorable timestamps across multiple transactions.
 * 
 * 2. **Time-Based Privilege Escalation**: Messages sent during "admin hours" (9 AM to 6 PM UTC) with high values (≥1000000) receive special "priority" treatment with doubled values. This creates a timestamp-dependent privilege system that can be exploited.
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * - **Transaction 1**: Attacker sends a regular message, establishing LastMsg.Time state
 * - **Transaction 2**: Attacker collaborates with miner to manipulate timestamp to either:
 *   a) Bypass the 5-minute cooldown (set timestamp to LastMsg.Time + 301 seconds)
 *   b) Ensure the transaction falls within "admin hours" for privilege escalation
 * - **Transaction 3+**: Continue exploiting the established state and timestamp manipulation
 * 
 * The vulnerability requires multiple transactions because:
 * 1. The cooldown check depends on persistent state (LastMsg.Time) from previous transactions
 * 2. The privilege escalation requires specific timing windows that may need multiple attempts
 * 3. The exploitation becomes more effective when chained across multiple message submissions
 * 
 * This creates a realistic vulnerability where timestamp manipulation combined with stateful logic enables attackers to bypass rate limiting and gain unauthorized privileges through coordinated multi-transaction attacks.
 */
pragma solidity ^0.4.19;

contract PRIVATE_ETH_CELL
{
    mapping (address=>uint256) public balances;   
   
    uint public MinSum;
    
    LogFile Log;
    
    bool intitalized;
    
    function SetMinSum(uint _val)
    public
    {
        require(!intitalized);
        MinSum = _val;
    }
    
    function SetLogFile(address _log)
    public
    {
        require(!intitalized);
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
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        // Check if enough time has passed since last message (anti-spam protection)
        if(LastMsg.Time > 0 && now - LastMsg.Time < 300) { // 5 minutes cooldown
            return; // Reject if too soon
        }
        
        // Time-based privilege escalation: messages sent during "admin hours" get special treatment
        bool isAdminHours = ((now % 86400) >= 32400 && (now % 86400) <= 64800); // 9 AM to 6 PM UTC
        
        // If it's admin hours and this is a high-value message, mark it as priority
        if(isAdminHours && _val >= 1000000) {
            LastMsg.Sender = _adr;
            LastMsg.Time = now;
            LastMsg.Val = _val * 2; // Double the value for "priority" messages
            LastMsg.Data = string(abi.encodePacked("PRIORITY: ", _data));
            History.push(LastMsg);
        } else {
            LastMsg.Sender = _adr;
            LastMsg.Time = now;
            LastMsg.Val = _val;
            LastMsg.Data = _data;
            History.push(LastMsg);
        }
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
    }
}