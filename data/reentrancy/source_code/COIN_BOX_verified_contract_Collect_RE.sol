/*
 * ===== SmartInject Injection Details =====
 * Function      : Collect
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 1 findings
 * Total Found   : 3 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-eth (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding a `pendingWithdrawals` mapping that tracks withdrawal amounts across transactions. The vulnerability requires multiple transactions to exploit:
 * 
 * **Transaction 1**: Initial legitimate call sets `pendingWithdrawals[attacker] = _am` and makes external call with this amount. The attacker's fallback function can reenter but cannot yet exploit due to balance constraints.
 * 
 * **Transaction 2**: Attacker calls again with a smaller amount. The function now sends the previously pending amount (from Transaction 1) but only deducts the current `_am` from balance. This creates a discrepancy where more ETH is sent than deducted.
 * 
 * **Transaction 3+**: Attacker can repeat the process, accumulating pending withdrawals while the actual balance deduction lags behind, allowing gradual draining of the contract.
 * 
 * **Key Multi-Transaction Elements:**
 * 1. **State Persistence**: `pendingWithdrawals` persists between transactions
 * 2. **Accumulated Effect**: Each transaction builds upon previous pending amounts
 * 3. **Progressive Exploitation**: Vulnerability becomes more severe with each additional transaction
 * 4. **Cross-Transaction Dependencies**: Later transactions depend on state set by earlier ones
 * 
 * The vulnerability is realistic because it introduces a common pattern of trying to "optimize" withdrawal processing by batching amounts, but fails to properly synchronize the external call amount with the balance deduction.
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
    
    // Declare the missing mapping used in Collect
    mapping (address => uint) public pendingWithdrawals;
    
    function SetMinSum(uint _val)
    public
    {
        if(intitalized) revert();
        MinSum = _val;
    }
    
    function SetLogFile(address _log)
    public
    {
        if(intitalized) revert();
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
        Holder storage acc = Acc[msg.sender];
        acc.balance += msg.value;
        if(now+_lockTime > acc.unlockTime) acc.unlockTime = now+_lockTime;
        Log.AddMessage(msg.sender,msg.value,"Put");
    }
    
    function Collect(uint _am)
    public
    payable
    {
        Holder storage acc = Acc[msg.sender];
        if( acc.balance>=MinSum && acc.balance>=_am && now>acc.unlockTime)
        {
            // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
            // Track withdrawal attempts across transactions
            if(pendingWithdrawals[msg.sender] == 0) {
                pendingWithdrawals[msg.sender] = _am;
            }
            
            // Allow external call with accumulated pending amount
            uint totalPending = pendingWithdrawals[msg.sender];
            if(msg.sender.call.value(totalPending)())
            {
                // State update occurs after external call - vulnerable to reentrancy
                acc.balance-=_am;
                
                // Only clear pending after successful state update
                if(acc.balance < MinSum) {
                    pendingWithdrawals[msg.sender] = 0;
                }
                
            // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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
