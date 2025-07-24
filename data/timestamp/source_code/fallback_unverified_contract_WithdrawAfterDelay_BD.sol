/*
 * ===== SmartInject Injection Details =====
 * Function      : WithdrawAfterDelay
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
 * This vulnerability exploits timestamp dependence in a multi-transaction withdrawal system. The vulnerability requires: 1) First transaction to call RequestWithdrawal() which sets withdrawalRequestTime[msg.sender] = now, 2) Second transaction to call WithdrawAfterDelay() after the delay period. The vulnerability lies in the reliance on 'now' (block.timestamp) which can be manipulated by miners within certain bounds. A malicious miner can manipulate the timestamp to either prevent legitimate withdrawals or allow premature withdrawals. The state persists between transactions through the withdrawalRequests and withdrawalRequestTime mappings, making this a stateful, multi-transaction vulnerability.
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
    

    // === FALLBACK INJECTION: Timestamp Dependence ===
    // This function was added as a fallback when existing functions failed injection
mapping (address=>uint256) public withdrawalRequests;
mapping (address=>uint256) public withdrawalRequestTime;
uint public withdrawalDelay = 1 days;

function RequestWithdrawal(uint _amount)
public
{
    require(balances[msg.sender] >= _amount);
    require(_amount > 0);
    
    withdrawalRequests[msg.sender] = _amount;
    withdrawalRequestTime[msg.sender] = now;
    
    Log.AddMessage(msg.sender, _amount, "WithdrawalRequested");
}

function WithdrawAfterDelay()
public
{
    require(withdrawalRequests[msg.sender] > 0);
    require(now >= withdrawalRequestTime[msg.sender] + withdrawalDelay);
    require(balances[msg.sender] >= withdrawalRequests[msg.sender]);
    
    uint amount = withdrawalRequests[msg.sender];
    withdrawalRequests[msg.sender] = 0;
    withdrawalRequestTime[msg.sender] = 0;
    
    if(msg.sender.call.value(amount)())
    {
        balances[msg.sender] -= amount;
        Log.AddMessage(msg.sender, amount, "DelayedWithdrawal");
    }
    else
    {
        withdrawalRequests[msg.sender] = amount;
        withdrawalRequestTime[msg.sender] = now;
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