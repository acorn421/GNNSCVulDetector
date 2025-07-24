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
 * Introduced a stateful, multi-transaction timestamp dependence vulnerability through rate limiting and priority message handling. The vulnerability allows miners to manipulate block.timestamp to bypass rate limits and gain priority status by controlling timing between transactions. This creates a multi-transaction exploit scenario where:
 * 
 * 1. **Rate Limiting Bypass**: Miners can manipulate block.timestamp within the 15-second tolerance to bypass the 60-second rate limit, allowing them to send multiple messages from the same address in quick succession when they should be rate-limited.
 * 
 * 2. **Priority Message Manipulation**: Miners can control the timing between their transactions and others' to consistently achieve priority status (messages sent within 30 seconds of the last message get "[PRIORITY]" prefix), giving them unfair advantage in message ordering.
 * 
 * 3. **Multi-Transaction Exploitation**: The vulnerability requires multiple transactions to be effective:
 *    - First transaction: Establish baseline timestamp in History array
 *    - Second transaction: Exploit timestamp manipulation to either bypass rate limit or gain priority
 *    - Additional transactions: Continue exploiting accumulated timestamp state
 * 
 * 4. **Accumulated State Dependency**: The vulnerability depends on the accumulated timestamp data in the History array, making it inherently multi-transaction and stateful. Each transaction builds upon the timestamp state from previous transactions.
 * 
 * The exploit leverages the fact that miners can set block.timestamp within reasonable bounds, allowing them to manipulate the timing calculations used for rate limiting and priority determination across multiple sequential transactions.
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
        // Rate limiting based on timestamp - allow only one message per 60 seconds per address
        if (History.length > 0) {
            for (uint i = History.length - 1; i >= 0; i--) {
                if (History[i].Sender == _adr && (now - History[i].Time) < 60) {
                    revert("Rate limit exceeded");
                }
                if (i == 0) break; // Prevent underflow
            }
        }
        
        // Priority message handling based on timestamp difference
        bool isPriority = false;
        if (History.length > 0) {
            uint timeDiff = now - History[History.length - 1].Time;
            // Messages sent within 30 seconds of the last message get priority status
            if (timeDiff <= 30) {
                isPriority = true;
            }
        }
        
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
        LastMsg.Sender = _adr;
        LastMsg.Time = now;
        LastMsg.Val = _val;
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        
        // Append priority indicator to data for priority messages
        if (isPriority) {
            LastMsg.Data = string(abi.encodePacked("[PRIORITY] ", _data));
        } else {
            LastMsg.Data = _data;
        }
        
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
        History.push(LastMsg);
    }
}