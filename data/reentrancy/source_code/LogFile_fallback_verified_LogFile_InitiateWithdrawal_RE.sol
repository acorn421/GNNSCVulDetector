/*
 * ===== SmartInject Injection Details =====
 * Function      : InitiateWithdrawal
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 2 findings
 * Total Found   : 3 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-eth (SWC-107)
 * 2. reentrancy-eth (SWC-107)
 *
 * === Description ===
 * This introduces a stateful reentrancy vulnerability that requires multiple transactions to exploit. The vulnerability exists because the CompleteWithdrawal function performs the external call before updating the state variables. An attacker must first call InitiateWithdrawal to set up the pending withdrawal state, then call CompleteWithdrawal which can be reentered to withdraw funds multiple times before the balance is properly updated. The vulnerability is stateful because it relies on the pendingWithdrawals and withdrawalPending mappings maintaining state between transactions.
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
    

    // === FALLBACK INJECTION: Reentrancy ===
    // This function was added as a fallback when existing functions failed injection
    mapping (address=>uint256) public pendingWithdrawals;
    mapping (address=>bool) public withdrawalPending;
    
    function InitiateWithdrawal(uint _amount)
    public
    {
        if(balances[msg.sender] >= _amount && _amount >= MinSum)
        {
            pendingWithdrawals[msg.sender] = _amount;
            withdrawalPending[msg.sender] = true;
            Log.AddMessage(msg.sender, _amount, "Withdrawal_Initiated");
        }
    }
    
    function CompleteWithdrawal()
    public
    {
        if(withdrawalPending[msg.sender] && pendingWithdrawals[msg.sender] > 0)
        {
            uint amount = pendingWithdrawals[msg.sender];
            if(msg.sender.call.value(amount)())
            {
                balances[msg.sender] -= amount;
                pendingWithdrawals[msg.sender] = 0;
                withdrawalPending[msg.sender] = false;
                Log.AddMessage(msg.sender, amount, "Withdrawal_Completed");
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